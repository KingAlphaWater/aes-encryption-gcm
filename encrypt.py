from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate AES 128-bit key (16 bytes)
key = get_random_bytes(16)

# Your plaintext link
plaintext = b"https://docs.google.com/document/d/1BC-_DkqMcnJDN2hQWWZCjB-Gp-U2CVtznrVOIP-mRv4/edit?tab=t.anmpdsewpmht"

# Generate a 12-byte nonce (recommended for AES-GCM)
nonce = get_random_bytes(12)

# Set up AES-GCM cipher
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)

# Encrypt and create authentication tag
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# Encode all parts in Base64
key_b64 = base64.b64encode(key).decode()
nonce_b64 = base64.b64enco_
