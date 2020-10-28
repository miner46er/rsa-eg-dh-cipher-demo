import util

class RSA():
    def __init__(self, private_key: bytes = None, public_key: bytes = None):
        self.num_bits = 1024
        self.block_size = self.num_bits // 8

        self.e = pow(2, 16) + 1

        if (public_key != None):
            self.n = int.from_bytes(public_key[:self.block_size], "little")
            self.e = int.from_bytes(public_key[self.block_size:], "little")

        if (private_key != None):
            self.n = int.from_bytes(private_key[:self.block_size], "little")
            self.d = int.from_bytes(private_key[self.block_size:], "little")

    def encrypt_block(self, block: bytes) -> bytes:
        if (not hasattr(self, "n") or not hasattr(self, "e")):
            raise AttributeError("No public key")

        block_int = int.from_bytes(block, "little")
        encrypted_block_int = pow(block_int, self.e, self.n)
        encrypted_block = encrypted_block_int.to_bytes(len(block), "little")
        return encrypted_block

    def decrypt_block(self, block: bytes) -> bytes:
        if (not hasattr(self, "n") or not hasattr(self, "d")):
            raise AttributeError("No private key")

        block_int = int.from_bytes(block, "little")
        decrypted_block_int = pow(block_int, self.d, self.n)
        decrypted_block = decrypted_block_int.to_bytes(len(block), "little")
        return decrypted_block

    def get_private_key(self) -> bytes:
        if (not hasattr(self, "n") or not hasattr(self, "d")):
            raise AttributeError("No private key")
        n_bytes = self.n.to_bytes(self.block_size, "little")
        d_bytes = self.d.to_bytes(self.block_size, "little")
        private_key = n_bytes + d_bytes
        return private_key

    def get_public_key(self) -> bytes:
        if (not hasattr(self, "n") or not hasattr(self, "e")):
            raise AttributeError("No public key")
        n_bytes = self.n.to_bytes(self.block_size, "little")
        e_bytes = self.e.to_bytes(self.block_size, "little")
        public_key = n_bytes + e_bytes
        return public_key

    def generate_key(self):
        while True:
            p = util.get_prime(self.num_bits//2)
            q = util.get_prime(self.num_bits//2)

            self.n = p * q

            # Ensure n is at least num_bits long in binary
            if not (self.n.bit_length() < self.num_bits):
                break

        tot = (p - 1) * (q - 1)
        self.e = pow(2, 16) + 1
        self.d = pow(self.e, -1, tot)
