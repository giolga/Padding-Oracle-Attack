from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16 # AES block size is 16 bytes
KEY = b"this_is_16_bytes"
# Ciphertext = IV + encrypted blocks (from check_decrypt.py success)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

# Task 1
def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False otherwise."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False
    
# Task 2
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]: 
    """Split data into blocks of the specified size.""" 
    blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        blocks.append(data[i: i+BLOCK_SIZE])
    
    return blocks

# Task 3
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes: 
    """
    Decrypt a single block using the padding oracle attack. 
    Returns the decrypted plaintext block. 
    """ 
    if(len(prev_block) != BLOCK_SIZE or len(target_block) != BLOCK_SIZE):
        raise ValueError("Blocks must be exactly BLOCK_SIZE bytes long.")
    
    i = bytearray(BLOCK_SIZE)
    p_i = bytearray(BLOCK_SIZE)

    forged_block = bytearray(prev_block) # C', The forged prev. block. IV functionality

    for j in range(BLOCK_SIZE - 1, -1, -1): # Run the loop backwards
        pad_val = BLOCK_SIZE - j

        for k in range(j + 1, BLOCK_SIZE):
            forged_block[k] = i[k] ^ pad_val # xor

        # Current byte brute force loop (C'[j])
        found_bytes = False
        for byte in range(256):
            forged_block[j] = byte
            test_ciphertext = bytes(forged_block + target_block)

            # Oracle
            if(padding_oracle(test_ciphertext)):
                found_bytes = True
                i[j] = forged_block[j] ^ pad_val
                p_i[j] = i[j] ^ prev_block[j]
                break
        
        if not found_bytes:
            raise Exception(f"Failed to find a valid guess for position {i} (padding {pad_val}).")
    
    return bytes(p_i)

# Task 4
def padding_oracle_attack(ciphertext: bytes) -> bytes: 
    """Perform the padding oracle attack on the entire ciphertext.""" 
    blocks = split_blocks(ciphertext)

    if len(blocks) < 2:
        raise ValueError("Ciphertext is too short to decrypt!")
    
    blocks_cnt = len(blocks) - 1
    decrypt_blocks = []

    for i in range(blocks_cnt):
        prev_block = blocks[i]
        target_block = blocks[i + 1]

        print(f"[*] Decrypting block {i+1}/{blocks_cnt}...")

        decrypted_block = decrypt_block(prev_block, target_block)
        decrypt_blocks.append(decrypted_block)

    return b"".join(decrypt_blocks)

# Task 5
def unpad_and_decode(plaintext: bytes) -> str: 
    """Attempt to unpad and decode the plaintext.""" 
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder() #Working with bits now
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
        return unpadded.decode('utf-8')
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        return f"Something went wrong! Couldn't unpad or decode! {e}"

if __name__ == "__main__": 
    try: 
        ciphertext = unhexlify(CIPHERTEXT_HEX) 
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes") 
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}") 
         
        recovered = padding_oracle_attack(ciphertext) 
         
        print("\n[+] Decryption complete!") 
        print(f" Recovered plaintext (raw bytes): {recovered}") 
        print(f" Hex: {recovered.hex()}") 
         
        decoded = unpad_and_decode(recovered) 
        print("\n Final plaintext:") 
        print(decoded) 
         
    except Exception as e: 
        print(f"\n Error occurred: {e}") 


    for i in CIPHERTEXT_HEX:
        padding_oracle(i)



    # data = b'A' * 16 + b'B' * 16 + b'C' * 16
    # print(data)
    # print(split_blocks(data, 16))

    # str = 'test.example chama'
    # sz = 5

    # print(str[2: 4])
    # print(str[sz:])