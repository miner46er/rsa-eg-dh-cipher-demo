import random

_first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 
                    31, 37, 41, 43, 47, 53, 59, 61, 67,  
                    71, 73, 79, 83, 89, 97, 101, 103,  
                    107, 109, 113, 127, 131, 137, 139,  
                    149, 151, 157, 163, 167, 173, 179,  
                    181, 191, 193, 197, 199, 211, 223, 
                    227, 229, 233, 239, 241, 251, 257, 
                    263, 269, 271, 277, 281, 283, 293, 
                    307, 311, 313, 317, 331, 337, 347, 349] 

_number_of_rabin_trials = 20 

def get_prime(number_of_bits):
    while True:
        prime_candidate = _get_low_level_prime(number_of_bits) 
        if not _is_miller_rabin_passed(prime_candidate): 
            continue
        else:
            return prime_candidate

def _n_bit_random(number_of_bits): 
    return random.randrange(2**(number_of_bits-1)+1, 2**number_of_bits - 1) 

def _get_low_level_prime(n): 
    while True: 
        prime_candidate = _n_bit_random(n)  

        for divisor in _first_primes_list: 
            if prime_candidate % divisor == 0 and divisor**2 <= prime_candidate: 
                break
            else:
                return prime_candidate 

def _is_miller_rabin_passed(prime_candidate): 
    max_divisions_by_two = 0
    ec = prime_candidate-1
    while ec % 2 == 0: 
        ec >>= 1
        max_divisions_by_two += 1
    assert(2**max_divisions_by_two * ec == prime_candidate-1) 

    def trial_composite(round_tester): 
        if pow(round_tester, ec, prime_candidate) == 1: 
            return False
        for i in range(max_divisions_by_two): 
            if pow(round_tester, 2**i * ec, prime_candidate) == prime_candidate-1: 
                return False
        return True

    for i in range(_number_of_rabin_trials): 
        round_tester = random.randrange(2, prime_candidate) 
        if trial_composite(round_tester): 
            return False
    return True
