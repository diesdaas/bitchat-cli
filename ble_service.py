# ble_service.py
import asyncio
import logging
import os
import struct
from typing import Dict, Optional
from bleak import BleakClient, BleakScanner, BLEDevice
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.exc import BleakError
from chat_state import ChatState
from protocol import BitchatPacket, BitchatMessage, BROADCAST_RECIPIENT
from encryption import EncryptionService

# Setup logging
logger = logging.getLogger(__name__)

# --- Constants ---
SERVICE_UUID = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
CHARACTERISTIC_UUID = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
CONNECTION_TIMEOUT = 15.0  # Increased timeout for more reliability
MAX_CONNECT_ATTEMPTS = 3   # Number of times to retry a connection
RETRY_DELAY = 2            # Seconds to wait before retrying
SCAN_TIMEOUT = 10.0        # Timeout for scanning


class BLEService:
    """Manages BLE scanning and connections with dual-mode (Central + Peripheral) support."""

    def __init__(self, state: ChatState, cli_redraw_callback):
        self.state = state
        self.clients: Dict[str, BleakClient] = {}
        self.encryption_service = EncryptionService()
        self.connecting_peers: set = set()
        self.cli_redraw = cli_redraw_callback
        self.scanner: Optional[BleakScanner] = None
        self.scanning = False
        self.server = None  # Will be BleakServer instance
        self.server_running = False

    def _parse_announce_packet(self, packet: BitchatPacket):
        """Parses ANNOUNCE packet payload to extract public keys."""
        try:
            payload = packet.payload
            offset = 0
            
            # Type 1: Nickname (8 bytes)
            if len(payload) >= offset + 2:
                type1, len1 = payload[offset], payload[offset + 1]
                offset += 2
                if type1 == 0x01 and len1 == 0x08 and len(payload) >= offset + 8:
                    nickname = payload[offset:offset + 8].rstrip(b'\x00').decode('utf-8', errors='ignore')
                    offset += 8
                    logger.info(f"ANNOUNCE: Nickname = {nickname}")
            
            # Type 2: Ed25519 public signing key (32 bytes)
            if len(payload) >= offset + 2:
                type2, len2 = payload[offset], payload[offset + 1]
                offset += 2
                if type2 == 0x02 and len2 == 0x20 and len(payload) >= offset + 32:
                    ed25519_key = payload[offset:offset + 32]
                    self.encryption_service.add_peer_signing_key(packet.sender_id, ed25519_key)
                    offset += 32
                    logger.info(f"ANNOUNCE: Extracted Ed25519 key for {packet.sender_id.hex()[:8]}")
            
            # Type 3: X25519 public key (32 bytes)
            if len(payload) >= offset + 2:
                type3, len3 = payload[offset], payload[offset + 1]
                offset += 2
                if type3 == 0x03 and len3 == 0x20 and len(payload) >= offset + 32:
                    x25519_key = payload[offset:offset + 32]
                    self.encryption_service.add_peer_public_key(packet.sender_id, x25519_key)
                    offset += 32
                    logger.info(f"ANNOUNCE: Extracted X25519 key for {packet.sender_id.hex()[:8]}")
        except Exception as e:
            logger.error(f"Failed to parse ANNOUNCE packet: {e}", exc_info=True)

    def notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Handles incoming data packets from peers when acting as Central."""
        try:
            logger.info(f"Notification received: {len(data)} bytes from characteristic {characteristic.uuid}")
            
            # Parse the received packet structure for comparison
            header_base_format = '>BB B Q B H'
            header_base_size = struct.calcsize(header_base_format)
            if len(data) >= header_base_size + 8:
                recv_version, recv_type, recv_ttl, recv_timestamp, recv_flags, recv_payload_len = struct.unpack(
                    header_base_format, bytes(data[:header_base_size])
                )
                recv_sender_id = bytes(data[header_base_size:header_base_size + 8])
                offset = header_base_size + 8
                recv_recipient_id = None
                if recv_flags & 1:  # HAS_RECIPIENT
                    recv_recipient_id = bytes(data[offset:offset + 8])
                    offset += 8
                recv_payload = bytes(data[offset:offset + recv_payload_len]) if len(data) >= offset + recv_payload_len else b''
                offset += recv_payload_len
                recv_signature = None
                if recv_flags & 2:  # HAS_SIGNATURE
                    recv_signature = bytes(data[offset:offset + 64]) if len(data) >= offset + 64 else None
                
                logger.info(f"=== RECEIVED PACKET STRUCTURE ===")
                logger.info(f"  Version: {recv_version}, Type: {recv_type}, TTL: {recv_ttl}")
                logger.info(f"  Flags: {recv_flags} (HAS_RECIPIENT={bool(recv_flags & 1)}, HAS_SIGNATURE={bool(recv_flags & 2)})")
                logger.info(f"  Payload length: {recv_payload_len}, Actual payload: {len(recv_payload)}")
                logger.info(f"  Sender ID: {recv_sender_id.hex()}")
                logger.info(f"  Recipient ID: {recv_recipient_id.hex() if recv_recipient_id else 'None'}")
                logger.info(f"  Has signature: {recv_signature is not None}")
                if recv_signature:
                    logger.info(f"  Signature (first 16 bytes): {recv_signature[:16].hex()}")
                    logger.info(f"  Signature (all zeros?): {all(b == 0 for b in recv_signature)}")
                logger.info(f"  Full packet size: {len(data)} bytes")
                logger.info(f"  First 32 bytes (hex): {bytes(data[:32]).hex()}")
                logger.info(f"  First 32 bytes (repr): {repr(bytes(data[:32]))}")
                logger.info(f"  Payload content: {recv_payload}")
                logger.info(f"=== END RECEIVED PACKET ===")
            
            packet = BitchatPacket.unpack(bytes(data))
            if packet:
                logger.info(f"Packet unpacked successfully: sender_id={packet.sender_id.hex()[:8]}..., my_id={self.state.my_peer_id.hex()[:8]}...")
                logger.info(f"Payload length: {len(packet.payload)} bytes")
                logger.info(f"Payload preview: {packet.payload[:100]}")
                
                # Handle ANNOUNCE packets: extract and store public keys
                if packet.type.value == 0x01:  # ANNOUNCE
                    self._parse_announce_packet(packet)
                
                # Validate signature if present
                if packet.signature and packet.sender_id != self.state.my_peer_id:
                    # Reconstruct the data that was signed
                    # The header format includes sender_id: '>BB B Q B H {8}s'
                    # So we need: header (with sender_id) + recipient_id + payload
                    header_format = f'>BB B Q B H {8}s'  # version, type, ttl, timestamp, flags, payload_len, sender_id
                    flags = 0
                    if packet.recipient_id is not None:
                        flags |= 1  # HAS_RECIPIENT
                    flags |= 2  # HAS_SIGNATURE (always present if signature exists)
                    
                    header = struct.pack(
                        header_format, packet.version, packet.type.value, packet.ttl,
                        packet.timestamp, flags, len(packet.payload), packet.sender_id
                    )
                    data_to_verify = header
                    if packet.recipient_id:
                        data_to_verify += packet.recipient_id
                    data_to_verify += packet.payload
                    
                    is_valid = self.encryption_service.verify_signature(
                        data_to_verify, packet.signature, packet.sender_id
                    )
                    if is_valid:
                        logger.info(f"✓ Signature valid for message from {packet.sender_id.hex()[:8]}")
                    else:
                        logger.warning(f"✗ Signature INVALID for message from {packet.sender_id.hex()[:8]}")
                        # Debug: log what we're verifying
                        logger.info(f"  Data to verify length: {len(data_to_verify)} bytes")
                        logger.info(f"  Data to verify (first 32 bytes): {data_to_verify[:32].hex()}")
                        logger.info(f"  Data to verify (full): {data_to_verify.hex()}")
                        logger.info(f"  Signature (first 16 bytes): {packet.signature[:16].hex()}")
                        logger.info(f"  Packet flags: {packet.type.value}, recipient: {packet.recipient_id.hex() if packet.recipient_id else 'None'}")
                
                if packet.sender_id != self.state.my_peer_id:
                    message = BitchatMessage.from_payload(packet.payload)
                    if message:
                        logger.info(f"Message parsed: {message.sender}: {message.content}")
                        self.state.add_message(message)
                        # Display the message and redraw the prompt
                        print(f"\n<{message.sender}>: {message.content}")
                        self.cli_redraw()
                    else:
                        logger.warning(f"Failed to parse message from payload. Payload: {packet.payload[:200]}")
                        logger.warning(f"Payload as string (attempt): {repr(packet.payload[:200])}")
                else:
                    logger.debug("Ignoring message from self")
            else:
                logger.warning(f"Failed to unpack packet from {len(data)} bytes")
                # Try to analyze the structure
                if len(data) >= 20:
                    try:
                        header_base_format = '>BB B Q B H'
                        header_base_size = struct.calcsize(header_base_format)
                        version, msg_type_val, ttl, timestamp, flags, payload_len = struct.unpack(
                            header_base_format, data[:header_base_size]
                        )
                        logger.warning(f"Header analysis: version={version}, type={msg_type_val}, ttl={ttl}, flags={flags}, payload_len={payload_len}")
                        logger.warning(f"Expected total size: {header_base_size + 8 + payload_len} bytes, got {len(data)} bytes")
                    except Exception as e:
                        logger.warning(f"Could not analyze header: {e}")
        except Exception as e:
            logger.error(f"Error handling notification: {e}", exc_info=True)

    async def characteristic_read_handler(self, characteristic: BleakGATTCharacteristic) -> bytearray:
        """Handler for read requests when acting as Peripheral."""
        # Return empty data for now, as we primarily use notifications
        return bytearray()

    async def characteristic_write_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Handler for write requests when acting as Peripheral."""
        try:
            logger.debug(f"Received write on characteristic {characteristic.uuid}: {len(data)} bytes")
            packet = BitchatPacket.unpack(bytes(data))
            if packet and packet.sender_id != self.state.my_peer_id:
                message = BitchatMessage.from_payload(packet.payload)
                if message:
                    self.state.add_message(message)
                    print(f"\n<{message.sender}>: {message.content}")
                    logger.debug(f"Received message via Peripheral mode from {message.sender}")
                    self.cli_redraw()
        except Exception as e:
            logger.error(f"Error handling characteristic write: {e}", exc_info=True)

    async def start_peripheral_server(self):
        """Starts the BLE Peripheral server to advertise this device."""
        try:
            # Try to import BleakServer - may not be available on all platforms
            try:
                from bleak import BleakServer
            except ImportError:
                logger.warning("BleakServer not available in this bleak version. Peripheral mode disabled.")
                print("[SYSTEM] [WARN] Peripheral mode not available. Only Central (scanning) mode will work.")
                print("[SYSTEM] [WARN] Other devices may not be able to discover this instance.")
                return
            
            logger.info("Starting BLE Peripheral server...")
            print("[SYSTEM] Starting BLE advertising (Peripheral mode)...")
            
            # Create server
            self.server = BleakServer()
            
            # Define characteristic properties
            from bleak.backends.characteristic import BleakGATTCharacteristicProperties
            
            char_props = (
                BleakGATTCharacteristicProperties.READ |
                BleakGATTCharacteristicProperties.WRITE |
                BleakGATTCharacteristicProperties.NOTIFY
            )
            
            # Set up write handler
            async def write_handler(characteristic, data):
                await self.characteristic_write_handler(characteristic, data)
            
            # Add service and characteristic
            await self.server.add_service(
                SERVICE_UUID,
                [
                    {
                        "uuid": CHARACTERISTIC_UUID,
                        "properties": char_props,
                        "descriptors": [],
                    }
                ]
            )
            
            # Register write handler
            self.server.set_write_handler(CHARACTERISTIC_UUID, write_handler)
            
            # Start the server
            await self.server.start()
            
            # Start advertising
            await self.server.start_advertising(
                name=self.state.nickname,
                service_uuids=[SERVICE_UUID],
            )
            
            self.server_running = True
            logger.info("BLE Peripheral server started and advertising")
            print(f"[SYSTEM] ✓ Advertising as '{self.state.nickname}' - other devices can now find you!")
            
        except AttributeError as e:
            # BleakServer API might be different
            logger.warning(f"BleakServer API issue: {e}. Peripheral mode disabled.")
            print("[SYSTEM] [WARN] Peripheral mode not supported on this platform/bleak version.")
            print("[SYSTEM] [WARN] Only Central (scanning) mode will work.")
            if self.server:
                try:
                    await self.server.stop()
                except:
                    pass
            self.server = None
            self.server_running = False
        except Exception as e:
            logger.error(f"Failed to start Peripheral server: {e}", exc_info=True)
            print(f"[SYSTEM] [ERROR] Failed to start advertising: {e}")
            print("[SYSTEM] [INFO] Continuing with Central (scanning) mode only.")
            if self.server:
                try:
                    await self.server.stop()
                except:
                    pass
            self.server = None
            self.server_running = False

    async def stop_peripheral_server(self):
        """Stops the BLE Peripheral server."""
        if self.server and self.server_running:
            try:
                await self.server.stop_advertising()
                await self.server.stop()
                self.server_running = False
                logger.info("BLE Peripheral server stopped")
                print("[SYSTEM] Peripheral server stopped.")
            except Exception as e:
                logger.error(f"Error stopping Peripheral server: {e}")

    def device_detection_callback(self, device: BLEDevice, advertisement_data):
        """Callback for when a device is detected during scanning."""
        try:
            # Check if device advertises our service UUID
            service_uuids = advertisement_data.service_uuids if hasattr(advertisement_data, 'service_uuids') else []
            
            # Also check if device name matches our pattern (optional)
            device_name = device.name or ""
            
            # Log detected device for debugging
            logger.debug(f"Detected device: {device.address} ({device_name}), Services: {service_uuids}")
            
            # Check if this is a bitchat peer
            is_bitchat_peer = (
                SERVICE_UUID.lower() in [uuid.lower() for uuid in service_uuids] or
                SERVICE_UUID.upper() in [uuid.upper() for uuid in service_uuids]
            )
            
            if is_bitchat_peer:
                # Check if already connected or connecting
                is_connected = device.address in self.clients
                is_connecting = device.address in self.connecting_peers
                
                # Also check if client is still actually connected
                if is_connected:
                    client = self.clients.get(device.address)
                    if client and not client.is_connected:
                        logger.info(f"Client {device.address} was disconnected, cleaning up")
                        self.on_disconnect(client)
                        is_connected = False
                
                if not is_connected and not is_connecting:
                    logger.info(f"Found bitchat peer: {device.address} ({device_name})")
                    print(f"[SYSTEM] Found peer: {device_name or device.address}")
                    self.connecting_peers.add(device.address)
                    asyncio.create_task(self.connect_to_device(device))
                else:
                    logger.debug(f"Ignoring already connected/connecting peer: {device.address}")
            else:
                logger.debug(f"Device {device.address} is not a bitchat peer (no matching service UUID)")
                
        except Exception as e:
            logger.error(f"Error in device detection callback: {e}")

    async def scan_and_connect(self):
        """Continuously scans for and connects to bitchat peers using callback-based scanning."""
        try:
            logger.info("Starting BLE scanner (Central mode)...")
            print("[SYSTEM] Starting BLE scanner (Central mode)...")
            
            # Try with service UUID filter first, fallback to scanning all devices
            try:
                self.scanner = BleakScanner(
                    service_uuids=[SERVICE_UUID],
                    detection_callback=self.device_detection_callback
                )
                logger.info("Scanner created with service UUID filter")
            except Exception as e:
                logger.warning(f"Could not create scanner with service UUID filter: {e}")
                logger.info("Falling back to scanning all devices")
                print("[SYSTEM] [INFO] Scanning all BLE devices (broader search)...")
                # Fallback: scan all devices and filter in callback
                self.scanner = BleakScanner(
                    detection_callback=self.device_detection_callback
                )
            
            self.scanning = True
            
            # Start scanning with callback
            try:
                async with self.scanner:
                    logger.info("Scanner started, waiting for devices...")
                    print("[SYSTEM] Scanner active - searching for bitchat peers...")
                    print("[SYSTEM] [TIP] Make sure other bitchat devices are nearby and advertising...")
                    
                    # Keep scanning indefinitely
                    while self.scanning:
                        await asyncio.sleep(1)
            except BleakError as e:
                logger.error(f"BLE Scanner error: {e}")
                print(f"[SYSTEM] [ERROR] Scanner failed: {e}. Please check your Bluetooth adapter.")
                print("[SYSTEM] [INFO] Make sure Bluetooth is enabled and you have necessary permissions.")
                self.scanning = False
        except Exception as e:
            logger.error(f"Unexpected error in scanner: {e}", exc_info=True)
            print(f"[SYSTEM] [ERROR] Unexpected scanner error: {e}")
            self.scanning = False

    async def connect_to_device(self, device: BLEDevice):
        """Establishes and validates a connection with retries."""
        logger.info(f"Attempting to connect to {device.address}")
        
        for attempt in range(MAX_CONNECT_ATTEMPTS):
            client = None
            try:
                print(
                    f"[SYSTEM] Connecting to {device.name or device.address} (Attempt {attempt + 1}/{MAX_CONNECT_ATTEMPTS})...")
                logger.debug(f"Connection attempt {attempt + 1} to {device.address}")
                self.cli_redraw()

                client = BleakClient(
                    device, disconnected_callback=self.on_disconnect)
                async with asyncio.timeout(CONNECTION_TIMEOUT):
                    await client.connect()

                if client.is_connected:
                    logger.info(f"Connected to {device.address}, validating...")
                    
                    # Validate the peer has the correct characteristic
                    # client.services is a property, not a method
                    target_characteristic = None
                    for service in client.services:
                        logger.debug(f"Service {service.uuid} has {len(service.characteristics)} characteristics")
                        for char in service.characteristics:
                            logger.debug(f"  Characteristic: {char.uuid} (props: {char.properties})")
                            if char.uuid.lower() == CHARACTERISTIC_UUID.lower():
                                target_characteristic = char
                                break
                        if target_characteristic:
                            break
                    
                    if target_characteristic:
                        peer_name = device.name or f"peer-{device.address[-5:]}"
                        print(
                            f"[SYSTEM] ✓ Connected to {peer_name} ({device.address})")
                        logger.info(f"Successfully connected and validated peer: {device.address}")
                        
                        self.clients[device.address] = client
                        self.state.add_peer(device.address, peer_name)
                        
                        # Start notifications using the actual characteristic instance
                        # This ensures we use the correct UUID format
                        await client.start_notify(target_characteristic.uuid, self.notification_handler)
                        logger.info(f"Started notifications for {device.address} on characteristic {target_characteristic.uuid}")
                        
                        # Send ANNOUNCE packet with our public keys so peer can validate our signatures
                        await self.send_announce_packet(client, target_characteristic)
                        
                        self.cli_redraw()
                        return  # Success, exit the retry loop and function
                    else:
                        logger.warning(f"Device {device.address} does not have required characteristic")
                        print(
                            f"[SYSTEM] Device {device.address} is not a valid bitchat peer. Ignoring.")
                        await client.disconnect()
                        # No need to retry for invalid peers
                        return
                        
            except asyncio.TimeoutError:
                logger.warning(f"Connection to {device.address} timed out (attempt {attempt + 1})")
                print(
                    f"[SYSTEM] [WARN] Connection to {device.address} timed out.")
            except BleakError as e:
                logger.warning(f"Connection to {device.address} failed: {e} (attempt {attempt + 1})")
                print(
                    f"[SYSTEM] [WARN] Connection failed: {e}")
            except Exception as e:
                logger.error(f"Unexpected error connecting to {device.address}: {e}")
                print(
                    f"[SYSTEM] [ERROR] Unexpected error: {e}")
                break  # Don't retry on unexpected errors
            finally:
                # Clean up if connection failed
                if client and not client.is_connected:
                    try:
                        await client.disconnect()
                    except:
                        pass
                    self.on_disconnect(client)

            if attempt < MAX_CONNECT_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_DELAY)

        logger.error(f"Failed to connect to {device.address} after {MAX_CONNECT_ATTEMPTS} attempts")
        print(
            f"[SYSTEM] Failed to connect to {device.address} after {MAX_CONNECT_ATTEMPTS} attempts.")
        self.connecting_peers.discard(device.address)
        self.cli_redraw()

    def on_disconnect(self, client: BleakClient):
        """Handles peer disconnection and cleans up resources."""
        address = client.address
        logger.info(f"Disconnect callback triggered for {address}")
        
        # This callback can be triggered for devices we failed to connect to,
        # so we check if they were ever truly 'connected'.
        if address in self.state.connected_peers:
            nickname = self.state.peer_nicknames.get(address, address)
            self.state.remove_peer(address)
            print(f"\n[SYSTEM] Peer '{nickname}' has disconnected.")
            logger.info(f"Peer {nickname} ({address}) disconnected")
            self.cli_redraw()

        if address in self.clients:
            del self.clients[address]
        self.connecting_peers.discard(address)

    async def send_announce_packet(self, client: BleakClient, characteristic):
        """Sends an ANNOUNCE packet with our public keys to allow signature validation."""
        from protocol import MessageType
        
        # Build ANNOUNCE payload: nickname + Ed25519 public key + X25519 public key
        # Format: [type][length][data]...
        # Type 1: Nickname (8 bytes)
        nickname_bytes = self.state.nickname.encode('utf-8')[:8].ljust(8, b'\x00')
        announce_payload = b'\x01\x08' + nickname_bytes
        
        # Type 2: Ed25519 public signing key (32 bytes)
        ed25519_pubkey = self.encryption_service.get_signing_public_key_bytes()
        announce_payload += b'\x02\x20' + ed25519_pubkey  # 0x20 = 32
        
        # Type 3: X25519 public key (32 bytes) for encryption
        x25519_pubkey = self.encryption_service.get_public_key_bytes()
        announce_payload += b'\x03\x20' + x25519_pubkey  # 0x20 = 32
        
        # Create ANNOUNCE packet
        packet = BitchatPacket(
            sender_id=self.state.my_peer_id,
            recipient_id=None,  # ANNOUNCE packets don't have recipient
            payload=announce_payload,
            type=MessageType.ANNOUNCE,  # Type 0x01
            signature=None  # Will add signature after signing
        )
        
        # Sign the packet (header + sender_id + payload, without signature)
        # ANNOUNCE packets have HAS_SIGNATURE flag but no HAS_RECIPIENT
        header_format = f'>BB B Q B H {8}s'
        flags = 2  # HAS_SIGNATURE (no recipient for ANNOUNCE)
        header = struct.pack(
            header_format, packet.version, packet.type.value, packet.ttl,
            packet.timestamp, flags, len(packet.payload), packet.sender_id
        )
        data_to_sign = header + packet.payload
        
        # Sign and add signature
        signature = self.encryption_service.sign(data_to_sign)
        packet.signature = signature
        
        # Pack and pad to 256 bytes
        data_to_send = packet.pack()
        if len(data_to_send) < 256:
            data_to_send = data_to_send + b'\x00' * (256 - len(data_to_send))
        
        # Send ANNOUNCE packet
        try:
            await client.write_gatt_char(characteristic.uuid, data_to_send, response=True)
            logger.info(f"Sent ANNOUNCE packet to {client.address} with public keys")
        except Exception as e:
            logger.warning(f"Failed to send ANNOUNCE packet to {client.address}: {e}")
            # Try without response
            try:
                await client.write_gatt_char(characteristic.uuid, data_to_send, response=False)
                logger.info(f"Sent ANNOUNCE packet (no response) to {client.address}")
            except Exception as e2:
                logger.error(f"Failed to send ANNOUNCE packet even without response: {e2}")

    async def broadcast(self, message: BitchatMessage):
        """Sends a message to all connected and validated peers."""
        message.sender = self.state.nickname
        
        # For compatibility with the phone app, send as plain text payload
        # The phone app seems to use MessageType 0x02 (KEY_EXCHANGE) for messages
        # and expects simple text payloads, not our string format
        from protocol import MessageType
        
        # Use simple text payload for compatibility
        simple_payload = message.content.encode('utf-8')
        
        # According to bitchat documentation: "Public local chat has no security concerns"
        # The phone app sends packets with HAS_RECIPIENT | HAS_SIGNATURE flags (flags=3)
        # BUT: Since we can't validate the phone's signatures, maybe signatures aren't actually required?
        # Let's try BOTH approaches: with and without signatures
        
        # APPROACH: Send WITHOUT signature (flags=1) - test if phone accepts unsigned messages
        # If this works, then signatures aren't required for public messages
        packet = BitchatPacket(
            sender_id=self.state.my_peer_id,
            recipient_id=BROADCAST_RECIPIENT,
            payload=simple_payload,
            type=MessageType.KEY_EXCHANGE,  # Use 0x02 like the phone app
            signature=None  # NO signature for public messages
        )
        
        data_to_send = packet.pack()

        # Pad packet to 256 bytes (BLE MTU) to match phone app behavior
        # The phone app always sends packets padded to 256 bytes
        if len(data_to_send) < 256:
            padding_needed = 256 - len(data_to_send)
            data_to_send = data_to_send + b'\x00' * padding_needed
        
        # Debug: Log the exact packet structure for comparison with received packets
        # Calculate flags manually for logging (HAS_RECIPIENT=1, HAS_SIGNATURE=2)
        calculated_flags = 0
        if packet.recipient_id is not None:
            calculated_flags |= 1  # HAS_RECIPIENT
        if packet.signature is not None:
            calculated_flags |= 2  # HAS_SIGNATURE
        
        # Parse our own packet to verify structure
        header_base_format = '>BB B Q B H'
        header_base_size = struct.calcsize(header_base_format)
        if len(data_to_send) >= header_base_size + 8:
            our_version, our_type, our_ttl, our_timestamp, our_flags, our_payload_len = struct.unpack(
                header_base_format, data_to_send[:header_base_size]
            )
            our_sender_id = data_to_send[header_base_size:header_base_size + 8]
            offset = header_base_size + 8
            our_recipient_id = None
            if our_flags & 1:  # HAS_RECIPIENT
                our_recipient_id = data_to_send[offset:offset + 8]
                offset += 8
            our_payload = data_to_send[offset:offset + our_payload_len]
            offset += our_payload_len
            our_signature = None
            if our_flags & 2:  # HAS_SIGNATURE
                our_signature = data_to_send[offset:offset + 64] if len(data_to_send) >= offset + 64 else None
        
        logger.info(f"Broadcasting message '{message.content}' ({len(data_to_send)} bytes, payload: {len(simple_payload)} bytes)")
        logger.info(f"=== OUR PACKET STRUCTURE ===")
        logger.info(f"  Version: {our_version}, Type: {our_type}, TTL: {our_ttl}")
        logger.info(f"  Flags: {our_flags} (calculated: {calculated_flags})")
        logger.info(f"  Payload length: {our_payload_len}, Actual payload: {len(our_payload)}")
        logger.info(f"  Sender ID: {our_sender_id.hex()}")
        logger.info(f"  Recipient ID: {our_recipient_id.hex() if our_recipient_id else 'None'}")
        logger.info(f"  Has signature: {our_signature is not None}")
        if our_signature:
            logger.info(f"  Signature (first 16 bytes): {our_signature[:16].hex()}")
            logger.info(f"  Signature (all zeros?): {all(b == 0 for b in our_signature)}")
            logger.info(f"  Signature length: {len(our_signature)} bytes (expected: 64)")
        logger.info(f"  Full packet size: {len(data_to_send)} bytes")
        logger.info(f"  First 32 bytes (hex): {data_to_send[:32].hex()}")
        logger.info(f"  First 32 bytes (repr): {repr(data_to_send[:32])}")
        logger.info(f"  Payload content: {our_payload}")
        logger.info(f"=== END OUR PACKET ===")
        
        # Compare with received packet structure
        logger.info(f"=== COMPARISON ===")
        logger.info(f"  Our flags: {our_flags}, Phone expects: 3 (HAS_RECIPIENT | HAS_SIGNATURE)")
        logger.info(f"  Our type: {our_type}, Phone sends: 2 (KEY_EXCHANGE)")
        logger.info(f"  Our packet size: {len(data_to_send)} bytes")
        logger.info(f"=== END COMPARISON ===")

        connected_clients = [client for client in self.clients.values() if client.is_connected]
        
        if not connected_clients:
            logger.warning("No connected clients to broadcast to")
            print("[SYSTEM] [WARN] No connected peers to send message to.")
            return

        logger.info(f"Broadcasting to {len(connected_clients)} peer(s)")
        
        tasks = []
        client_addresses = []
        for addr, client in self.clients.items():
            if client.is_connected:
                # BLE MTU is typically 256 bytes. Some implementations might expect packets
                # to be padded to MTU size. Let's try padding to 256 bytes.
                padded_data = data_to_send
                if len(padded_data) < 256:
                    # Pad with zeros to match BLE MTU
                    padded_data = data_to_send + b'\x00' * (256 - len(data_to_send))
                    logger.debug(f"Padded packet from {len(data_to_send)} to {len(padded_data)} bytes for {addr}")
                
                # Try with response=True first - some BLE implementations require acknowledgment
                # If that fails, we can fall back to response=False
                try:
                    tasks.append(
                        client.write_gatt_char(CHARACTERISTIC_UUID,
                                             padded_data, response=True)
                    )
                    client_addresses.append(addr)
                    logger.debug(f"Using response=True for {addr}, sending {len(padded_data)} bytes")
                except Exception as e:
                    logger.warning(f"Failed to use response=True for {addr}, trying response=False: {e}")
                    tasks.append(
            client.write_gatt_char(CHARACTERISTIC_UUID,
                                             padded_data, response=False)
                    )
                    client_addresses.append(addr)
                    logger.debug(f"Using response=False for {addr}, sending {len(padded_data)} bytes")
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = 0
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    failed_client_addr = client_addresses[i]
                    logger.error(f"Failed to send message to {failed_client_addr}: {result}")
                    print(
                        f"[SYSTEM] [ERROR] Failed to send message to {failed_client_addr}: {result}")
                else:
                    success_count += 1
                    logger.info(f"Successfully sent message to {client_addresses[i]}")
            
            if success_count > 0:
                logger.info(f"Message sent successfully to {success_count}/{len(tasks)} peer(s)")
            else:
                logger.warning(f"Failed to send message to all {len(tasks)} peer(s)")

    async def shutdown(self):
        """Clean shutdown of all BLE services."""
        logger.info("Shutting down BLE service...")
        self.scanning = False
        
        # Stop peripheral server
        await self.stop_peripheral_server()
        
        # Disconnect all clients
        disconnect_tasks = [
            client.disconnect() for client in self.clients.values() if client.is_connected
        ]
        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
        
        logger.info("BLE service shutdown complete")
