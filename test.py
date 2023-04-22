from dh import dh
from Crypto.Util import number
import random
from Crypto.Util.number import getStrongPrime
import sympy

def generate_dh_params():
    # Choose a large prime p
    # Choose a large prime p
    while True:
        # Generate a random 128-bit number
        p = random.getrandbits(128)

        # Ensure the number is odd
        if p % 2 == 0:
            continue

        # Test for primality using the Miller-Rabin test with 40 rounds
        if sympy.isprime(p):
            print(p)
            break
    # Find a primitive root g modulo p
    while True:
        g = random.randint(2, p - 2)
        if pow(g, (p - 1) // 2, p) == 1 and pow(g, (p - 1) // 3, p) != 1:
            break

    return p, g
# Generate a 2048-bit prime number
DPH_VALUES =  188820646289024943196740280087076087567,76526550457502878897718726024790070449

client_1 = dh()
client_2 =dh()
# DPH_VALUES =  generate_dh_params()

client_1.set_dh_numbers(DPH_VALUES[0],DPH_VALUES[1])
client_2.set_dh_numbers(DPH_VALUES[0],DPH_VALUES[1])

client_1.generate_keys()
client_2.generate_keys()

client_1_pub = client_1.get_public_key()
client_2_pub = client_2.get_public_key()
#pub1= 15
#pub2 = 22
mutel_key1 = client_1.exchange(client_2_pub)
mutel_key2 = client_2.exchange(client_1_pub)

print('first',str(mutel_key1))
print('second',str(mutel_key2))
if mutel_key1 == mutel_key2:
    print('good')
else:
    print('not equel')