import hashlib

aes_sbox_bytes = b'c|w{\xf2ko\xc50\x01g+\xfe\xd7\xabv\xca\x82\xc9}\xfaYG\xf0\xad\xd4\xa2\xaf\x9c\xa4r\xc0\xb7\xfd\x93&6?\xf7\xcc4\xa5\xe5\xf1q\xd81\x15\x04\xc7#\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\'\xb2u\t\x83,\x1a\x1bnZ\xa0R;\xd6\xb3)\xe3/\x84S\xd1\x00\xed \xfc\xb1[j\xcb\xbe9JLX\xcf\xd0\xef\xaa\xfbCM3\x85E\xf9\x02\x7fP<\x9f\xa8Q\xa3@\x8f\x92\x9d8\xf5\xbc\xb6\xda!\x10\xff\xf3\xd2\xcd\x0c\x13\xec_\x97D\x17\xc4\xa7~=d]\x19s`\x81O\xdc"*\x90\x88F\xee\xb8\x14\xde^\x0b\xdb\xe02:\nI\x06$\\\xc2\xd3\xacb\x91\x95\xe4y\xe7\xc87m\x8d\xd5N\xa9lV\xf4\xeaez\xae\x08\xbax%.\x1c\xa6\xb4\xc6\xe8\xddt\x1fK\xbd\x8b\x8ap>\xb5fH\x03\xf6\x0ea5W\xb9\x86\xc1\x1d\x9e\xe1\xf8\x98\x11i\xd9\x8e\x94\x9b\x1e\x87\xe9\xceU(\xdf\x8c\xa1\x89\r\xbf\xe6BhA\x99-\x0f\xb0T\xbb\x16'

class Shamaq():
    '''
    Block cipher algorithm that utilizes Feistel Network Cipher
    as its base and SHA as key expansion mechanism.
    '''
    def __init__(self, key):
        self.round_count = 8
        self.block_size = 8 # 8 bytes, 64 bits
        self.keys = self.generate_round_keys(key, self.round_count, self.block_size)

    def generate_round_keys(self, key, round_count, block_size):
        half_block_size = block_size // 2

        # Generate an expanded key using sha3_256 algorithm
        key_data = hashlib.sha3_256(key).digest()

        # Divide the expanded key to half block sub-keys for every round
        keys = [key_data[half_block_size * x: half_block_size * (x + 1)] for x in range(round_count)]

        return keys

    def _xor(self, a, b):
        a_i = int.from_bytes(a, "little")
        b_i = int.from_bytes(b, "little")
        xor_i = a_i ^ b_i

        return xor_i.to_bytes(len(a), "little")

    def _rot_r(self, a, n):
        n = n % len(a)

        return a[n:] + a[:n]

    def _sub_byte(self, byte):
        row = byte >> 4
        column = byte & 0xf

        return aes_sbox_bytes[row * 16 + column]

    def _sub(self, a):
        subbed_bytes = [self._sub_byte(x) for x in a]

        return bytes(subbed_bytes)

    def _reverse(self, block):
        L = block[:self.block_size//2]
        R = block[self.block_size//2:]
        return R + L

    def round(self, block, round_key):
        L = block[:self.block_size//2]
        R = block[self.block_size//2:]

        Rprime = self._xor(R, round_key)
        Rprime = self._sub(Rprime)
        Rprime = self._rot_r(Rprime, round_key[0])

        L = self._xor(L, Rprime)

        return R + L

    def encrypt_block(self, block):
        # Rounds
        for i in range(self.round_count):
            block = self.round(block, self.keys[i])

        # Reverse half-block
        block = self._reverse(block)

        return block

    def decrypt_block(self, block):
        # Decrypt is identical except the key order is reversed

        # Rounds
        for i in range(self.round_count - 1, -1, -1):
            block = self.round(block, self.keys[i])

        # Reverse half-block
        block = self._reverse(block)

        return block
