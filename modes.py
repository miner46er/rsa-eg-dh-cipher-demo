import iterator
import pkcs

class ModeOfOperation():
    def __init__(self, cipher):
        self.cipher = cipher

        self.block_size_ciphertext = cipher.block_size

        if hasattr(cipher, "block_size_plaintext"):
            self.block_size_plaintext = cipher.block_size_plaintext
        else:
            self.block_size_plaintext = cipher.block_size

        self.padding_scheme = pkcs.PKCS7(self.block_size_plaintext)

    def encrypt(self, block_iterator):
        yield

    def decrypt(self, block_iterator):
        yield

class ECB(ModeOfOperation):
    def __init__(self, cipher):
        super().__init__(cipher)

    def encrypt(self, block_iterator):
        eof_iterator = iterator.eof_signal_iterator(block_iterator)

        for block, eof in eof_iterator:
            if not eof:
                if len(block) != self.block_size_plaintext:
                    raise Exception("Iterator error: Block iterator returned data that is not a multiple of the specified plaintext block length")

                yield self.cipher.encrypt_block(block)

            else:
                block = self.padding_scheme.apply(block)

                if (len(block) % self.block_size_plaintext) != 0:
                    raise Exception("Padding error: Padding scheme returned data that is not a multiple of the block length")

                for x in range(0, len(block), self.block_size_plaintext):
                    yield self.cipher.encrypt_block(block[x:x+self.block_size_plaintext])

    def decrypt(self, block_iterator):
        eof_iterator = iterator.eof_signal_iterator(block_iterator)

        for block, eof in eof_iterator:
            if not eof:
                if len(block) != self.block_size_ciphertext:
                    raise Exception("Iterator error: Block iterator returned data that is not a multiple of the specified ciphertext block length")
                yield self.cipher.decrypt_block(block)

            else:
                decrypted_block = self.cipher.decrypt_block(block)
                decrypted_block = self.padding_scheme.remove(decrypted_block)
                if len(decrypted_block) != 0:
                    yield decrypted_block
