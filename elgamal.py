import random

# 1024 bits constant for modulus
PRIME = 127395837530650545756281042941338801224705787032847906276140539716804800147725223783492654614623319099907080271128074235077045467379916117567453253436945059098899192150895716852663313813338788543286759697857654121812437196900880932525836485292323142035006630048183820363390128785813351906033275700796868898923

class Elgamal():
    def __init__(self, private_key: bytes = None, public_key: bytes = None):
        self.num_bits = 1024
        self.block_size = self.num_bits // 8
        self.block_size_plaintext = self.block_size - 1

        if (public_key != None):
            self.p = int.from_bytes(public_key[:self.block_size], "little")
            self.g = int.from_bytes(public_key[self.block_size:self.block_size * 2], "little")
            self.y = int.from_bytes(public_key[self.block_size * 2:], "little")

        if (private_key != None):
            self.p = int.from_bytes(private_key[:self.block_size], "little")
            self.x = int.from_bytes(private_key[self.block_size:], "little")

    def encrypt_block(self, block: bytes) -> (bytes, bytes):
        if (not hasattr(self, "g") or not hasattr(self, "y")):
            raise AttributeError("No public key")
        if (not (len(block) == self.block_size_plaintext)):
            raise BufferError("Invalid block length, expected " + str(self.block_size_plaintext) + " bytes")

        k = random.randrange(1, self.g)

        block_int = int.from_bytes(block, "little")
        encrypted_block_a_int = pow(self.g, k, self.p)
        encrypted_block_b_int = (pow(self.y, k, self.p) * block_int) % self.p
        encrypted_block_a = encrypted_block_a_int.to_bytes(self.block_size, "little")
        encrypted_block_b = encrypted_block_b_int.to_bytes(self.block_size, "little")
        return (encrypted_block_a, encrypted_block_b)

    def decrypt_block(self, block: (bytes, bytes)) -> bytes:
        if (not hasattr(self, "p") or not hasattr(self, "x")):
            raise AttributeError("No private key")
        if (not (len(block[0]) == self.block_size and len(block[1]) == self.block_size)):
            raise BufferError("Invalid block length, expected " + str(self.block_size) + " bytes")

        block_a_int = int.from_bytes(block[0], "little")
        block_b_int = int.from_bytes(block[1], "little")
        ax_inverse = pow(block_a_int, self.p-1-self.x, self.p)
        decrypted_block_int = (block_b_int * ax_inverse) % self.p
        decrypted_block = decrypted_block_int.to_bytes(self.block_size_plaintext, "little")
        return decrypted_block

    def get_private_key(self) -> bytes:
        if (not hasattr(self, "p") or not hasattr(self, "x")):
            raise AttributeError("No private key")
        p_bytes = self.p.to_bytes(self.block_size, "little")
        x_bytes = self.d.to_bytes(self.block_size, "little")
        private_key = p_bytes + x_bytes
        return private_key

    def get_public_key(self) -> bytes:
        if (not hasattr(self, "p") or not hasattr(self, "g") or not hasattr(self, "y")):
            raise AttributeError("No public key")
        p_bytes = self.p.to_bytes(self.block_size, "little")
        g_bytes = self.g.to_bytes(self.block_size, "little")
        y_bytes = self.y.to_bytes(self.block_size, "little")
        public_key = p_bytes + g_bytes + y_bytes
        return public_key

    def generate_key(self):
        self.p = PRIME
        self.g = random.randrange(0, self.p)
        self.x = random.randrange(0, self.p)
        self.y = pow(self.g, self.x, self.p)
