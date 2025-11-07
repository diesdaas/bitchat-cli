# encryption.py
import logging
import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger(__name__)


class EncryptionService:
    """
    Manages cryptographic keys and operations for secure communication.
    A conceptual Python implementation of the Swift EncryptionService.
    """

    def __init__(self):
        # In a real app, these would be loaded from a secure store.
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.peer_public_keys: dict[bytes, x25519.X25519PublicKey] = {}
        self.shared_secrets: dict[bytes, bytes] = {}
        
        # Ed25519 key pair for signing messages (64-byte signatures)
        self.signing_key = Ed25519PrivateKey.generate()
        self.signing_public_key = self.signing_key.public_key()
        
        # Store peer Ed25519 public keys for signature verification
        self.peer_signing_keys: dict[bytes, ed25519.Ed25519PublicKey] = {}

    def get_public_key_bytes(self) -> bytes:
        """Returns the raw public key for exchange."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def add_peer_public_key(self, peer_id: bytes, peer_key_bytes: bytes):
        """Adds a peer's public key and computes the shared secret."""
        try:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(
                peer_key_bytes)
            self.peer_public_keys[peer_id] = peer_public_key
            shared_secret = self.private_key.exchange(peer_public_key)
            # In a real implementation, you would use a KDF like HKDF here.
            self.shared_secrets[peer_id] = shared_secret
            print(f"Computed shared secret with peer {peer_id.hex()}")
        except Exception as e:
            print(f"Failed to add peer public key: {e}")

    def encrypt(self, data: bytes, peer_id: bytes) -> Optional[bytes]:
        """Encrypts data for a specific peer."""
        shared_secret = self.shared_secrets.get(peer_id)
        if not shared_secret:
            return None
        # Using first 16 bytes of secret as key for AES-128-GCM for simplicity.
        aesgcm = AESGCM(shared_secret[:16])
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, data, None)

    def decrypt(self, data: bytes, peer_id: bytes) -> Optional[bytes]:
        """Decrypts data from a specific peer."""
        shared_secret = self.shared_secrets.get(peer_id)
        if not shared_secret or len(data) < 12:
            return None
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(shared_secret[:16])
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:  # InvalidTag
            return None
    
    def sign(self, data: bytes) -> bytes:
        """
        Signs data using Ed25519.
        Returns a 64-byte signature.
        """
        return self.signing_key.sign(data)
    
    def get_signing_public_key_bytes(self) -> bytes:
        """Returns the raw public key for signature verification (32 bytes)."""
        return self.signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def add_peer_signing_key(self, peer_id: bytes, peer_key_bytes: bytes):
        """Adds a peer's Ed25519 public signing key for signature verification."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            peer_signing_key = Ed25519PublicKey.from_public_bytes(peer_key_bytes)
            self.peer_signing_keys[peer_id] = peer_signing_key
            logger.info(f"Added Ed25519 signing key for peer {peer_id.hex()[:8]}")
        except Exception as e:
            logger.error(f"Failed to add peer signing key: {e}")
    
    def verify_signature(self, data: bytes, signature: bytes, peer_id: bytes) -> bool:
        """Verifies a signature using the peer's public key."""
        peer_key = self.peer_signing_keys.get(peer_id)
        if not peer_key:
            logger.warning(f"No signing key for peer {peer_id.hex()[:8]}, cannot verify")
            return False
        try:
            peer_key.verify(signature, data)
            return True
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False
