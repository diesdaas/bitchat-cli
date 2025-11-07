# ble_service.py
import asyncio
import logging
import struct
from typing import Dict, Optional
from bleak import BleakClient, BleakScanner, BLEDevice
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.exc import BleakError
from chat_state import ChatState
from protocol import BitchatPacket, BitchatMessage, BROADCAST_RECIPIENT

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
        self.connecting_peers: set = set()
        self.cli_redraw = cli_redraw_callback
        self.scanner: Optional[BleakScanner] = None
        self.scanning = False
        self.server = None  # Will be BleakServer instance
        self.server_running = False

    def notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Handles incoming data packets from peers when acting as Central."""
        try:
            logger.info(f"Notification received: {len(data)} bytes from characteristic {characteristic.uuid}")
            # Log first 64 bytes in hex for debugging
            hex_preview = data.hex()[:128]  # First 64 bytes as hex string
            logger.info(f"First 64 bytes (hex): {hex_preview}...")
            logger.info(f"First 32 bytes (repr): {repr(bytes(data[:32]))}")
            
            packet = BitchatPacket.unpack(bytes(data))
            if packet:
                logger.info(f"Packet unpacked successfully: sender_id={packet.sender_id.hex()[:8]}..., my_id={self.state.my_peer_id.hex()[:8]}...")
                logger.info(f"Payload length: {len(packet.payload)} bytes")
                logger.info(f"Payload preview: {packet.payload[:100]}")
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
            logger.error(f"Error handling characteristic write: {e}")

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

    async def broadcast(self, message: BitchatMessage):
        """Sends a message to all connected and validated peers."""
        message.sender = self.state.nickname
        packet = BitchatPacket(
            sender_id=self.state.my_peer_id,
            recipient_id=BROADCAST_RECIPIENT,
            payload=message.to_payload()
        )
        data_to_send = packet.pack()
        
        logger.info(f"Broadcasting message '{message.content}' ({len(data_to_send)} bytes)")

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
                tasks.append(
                    client.write_gatt_char(CHARACTERISTIC_UUID,
                                         data_to_send, response=False)
                )
                client_addresses.append(addr)
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    failed_client_addr = client_addresses[i]
                    logger.error(f"Failed to send message to {failed_client_addr}: {result}")
                    print(
                        f"[SYSTEM] [ERROR] Failed to send message to {failed_client_addr}: {result}")
                else:
                    logger.debug(f"Successfully sent message to {client_addresses[i]}")

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
