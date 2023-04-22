import sys
import random
import sympy
num = 23
bt_num = num.to_bytes(sys.getsizeof(num),'little')
print(bt_num)

def lower(num:bytes):
    size = len(num)
    while num[-1] == 0:
        num= num[:-1]
        size-=1
    return size


def generate_dh_params():
    # Choose a large prime p
    while True:
        # Generate a random 128-bit number
        p = random.getrandbits(128)

        # Ensure the number is odd
        if p%2==0:
            continue

        # Test for primality using the Miller-Rabin test with 40 rounds
        if sympy.isprime(p):
            print(p)
            break
    # Find a primitive root g modulo p
    while True:
        g = random.randint(2, p-2)
        if pow(g, (p-1)//2, p) == 1 and pow(g, (p-1)//3, p) != 1:
            break

    return p, g

print(generate_dh_params())