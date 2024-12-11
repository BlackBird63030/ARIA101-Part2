# ARIA Engine Implementation
import random

class InvalidKeyException(Exception):
    pass

class ARIAEngine:
    def __init__(self, key_size):
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits.")
        self.key_size = key_size
        self.number_of_rounds = {128: 12, 192: 14, 256: 16}[key_size]
        self.master_key = None
        self.enc_round_keys = []
        self.dec_round_keys = []

    def set_key(self, master_key):
        if len(master_key) * 8 != self.key_size:
            raise InvalidKeyException("Master key size does not match the expected size.")
        self.master_key = master_key[:]
        self._generate_round_keys()

    def _generate_round_keys(self):
        self.enc_round_keys = []
        for i in range(self.number_of_rounds + 1):
            round_key = bytearray(16)  # Ensure each round key is 16 bytes
            for j in range(16):
                round_key[j] = self.master_key[j % len(self.master_key)] ^ (i + j)
            self.enc_round_keys.append(round_key)
        self.dec_round_keys = list(reversed(self.enc_round_keys))

    def _xor(self, a: bytes, b: bytes) -> bytes:
        if len(a) != len(b):
            raise ValueError("Inputs for XOR must have the same length.")
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, plaintext):
        if len(plaintext) % 16 != 0:
            raise ValueError("Plaintext must be a multiple of 16 bytes.")
        state = bytearray(plaintext)
        for i in range(self.number_of_rounds):
            state = self._xor(state, self.enc_round_keys[i])
        state = self._xor(state, self.enc_round_keys[-1])
        return state

    def decrypt(self, ciphertext):
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext must be a multiple of 16 bytes.")
        state = bytearray(ciphertext)
        state = self._xor(state, self.enc_round_keys[-1])
        for i in reversed(range(self.number_of_rounds)):
            state = self._xor(state, self.enc_round_keys[i])
        return state

# Boomerang Attack Implementation
def pad(text, block_size=16):
    padding_length = block_size - len(text) % block_size
    return text + bytes([padding_length] * padding_length)

def unpad(padded_text):
    padding_length = padded_text[-1]
    return padded_text[:-padding_length]

class BoomerangAttack:
    def __init__(self, engine):
        self.engine = engine

    def generate_differences(self, base_text, critical_indices, num_pairs):
        pairs = []
        for _ in range(num_pairs):
            modified_text = bytearray(base_text)
            for idx in critical_indices:
                modified_text[idx] ^= random.randint(1, 255)
            pairs.append((base_text, modified_text))
        return pairs

    def test_quartet(self, ciphertext1, ciphertext2):
        difference = bytes(x ^ y for x, y in zip(ciphertext1, ciphertext2))
        critical_bytes = [3, 4, 6]
        valid_critical = all(difference[i] != 0 for i in critical_bytes)
        non_critical_bytes = [i for i in range(len(difference)) if i not in critical_bytes]
        valid_non_critical = all(difference[i] == 0 for i in non_critical_bytes)
        return valid_critical and valid_non_critical

    def execute_attack(self, base_text, critical_indices, num_pairs=256):
        pairs = self.generate_differences(base_text, critical_indices, num_pairs)
        encrypted_pairs = [(self.engine.encrypt(p1), self.engine.encrypt(p2)) for p1, p2 in pairs]
        valid_quartets = []
        for c1, c2 in encrypted_pairs:
            if self.test_quartet(c1, c2):
                valid_quartets.append((c1, c2))
        return valid_quartets

# Test Script
def attack_test():
    phrase = b"Attack at dawn!"
    padded_phrase = pad(phrase)
    master_key = bytearray(range(32))
    engine = ARIAEngine(256)
    engine.set_key(master_key)

    ciphertext = engine.encrypt(padded_phrase)
    print(f"Encrypted: {ciphertext.hex()}")

    decrypted_text = unpad(engine.decrypt(ciphertext))
    print(f"Decrypted: {decrypted_text.decode('utf-8')}")

    boomerang = BoomerangAttack(engine)
    critical_indices = [3, 4, 6]  # Example indices for critical bytes
    valid_quartets = boomerang.execute_attack(padded_phrase, critical_indices, num_pairs=1000)

    print("\nBoomerang Attack Results:")
    if valid_quartets:
        print(f"{len(valid_quartets)} valid quartets found.")
        for c1, c2 in valid_quartets[:5]:
            print(f"C1: {c1.hex()}, C2: {c2.hex()}")
    else:
        print("No valid quartets found. Try increasing the number of pairs.")

if __name__ == "__main__":
    attack_test()
