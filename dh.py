import random
import util

NUM_BITS = 1024
GENERATOR = 2

class DiffieHellman():
    @staticmethod
    def get_n():
        return util.get_prime(NUM_BITS)

    @staticmethod
    def get_g(n):
        return GENERATOR

    @staticmethod
    def get_x(n):
        return random.randrange(0, n)

    @staticmethod
    def get_Y(n, g, x):
        return pow(g, x, n)

    @staticmethod
    def get_symetric_key(g, x, y, n):
        return pow(y, x, n)
