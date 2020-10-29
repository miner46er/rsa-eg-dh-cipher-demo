class PKCS7():
    def __init__(self, block_size):
        self.block_size = block_size

    def apply(self, block):
        if len(block) == self.block_size:
            return block + bytes([self.block_size] * self.block_size)
        else:
            n = self.block_size - len(block)
            return block + bytes([n] * n)

    def remove(self, block):
        if len(block) != self.block_size:
            raise Exception("Padding error: Unexpected block size")
        padding_length = int(block[-1])
        padding = block[-padding_length:]
        
        if padding_length == 0:
            return block

        for pad_val in padding:
            if pad_val != padding_length:
                raise Exception("Padding error: Invalid padding value ({})".format(pad_val))

        return block[:-padding_length]
