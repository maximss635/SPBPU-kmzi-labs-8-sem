import math
import random
import rsa.common
import rsa.prime
import argparse
from time import time
from attacks import *


def generate_keys_with_common_n(bits):
    # Первый ключ
    _, private_key_1 = rsa.newkeys(bits)

    # Второй ключ на тех же p, q, n но новые e, d
    e = 0b1000000000000000000000001
    d = rsa.common.inverse(e, (private_key_1.p - 1) * (private_key_1.q - 1))
    private_key_2 = rsa.PrivateKey(private_key_1.n, e, d, private_key_1.p, private_key_1.q)

    print('p = {}'.format(private_key_1.p))
    print('q = {}'.format(private_key_1.q))
    print('n = {}'.format(private_key_1.n))

    print('\nПервый ключ:')
    print('e = {}'.format(private_key_1.e))
    print('d = {}'.format(private_key_1.d))

    print('\nВторой ключ:')
    print('e = {}'.format(private_key_2.e))
    print('d = {}\n'.format(private_key_2.d))

    return private_key_1, private_key_2


def try_attack_1():
    private_key_1, private_key_2 = generate_keys_with_common_n(2048)

    attack = AttackCommonModule(private_key_1.n, private_key_1.e, private_key_1.d)
    p_attacked, q_attacked, d_attacked = attack(private_key_2.e)

    if private_key_2.p == p_attacked and private_key_2.q == q_attacked and \
            private_key_2.d == d_attacked:
        print('Атака прошла успешно')
    else:
        print('Атака прошла безуспешно')


def try_attack_2():
    # public_key, private_key = rsa.newkeys(128)
    public_key = rsa.PublicKey(793097, 678271)
    private_key = rsa.PrivateKey(793097, 678271, 7, 863, 919)

    print('Ключ:')
    print('p = {}'.format(private_key.p))
    print('q = {}'.format(private_key.q))
    print('n = {}'.format(private_key.n))
    print('e = {}'.format(private_key.e))
    print('d = {}'.format(private_key.d))

    attack = AttackViner()
    private_key_attacked = attack(public_key)

    if private_key.d == private_key_attacked:
        print('Атака прошла успешно')
    else:
        print('Атака прошла безуспешно')


def try_attack_3():
    # public_key, private_key = rsa.newkeys(64, exponent=50)
    public_key = rsa.PublicKey(793097, 678271)
    private_key = rsa.PrivateKey(793097, 678271, 7, 863, 919)

    print('Ключ:')
    print('p = {}'.format(private_key.p))
    print('q = {}'.format(private_key.q))
    print('n = {}'.format(private_key.n))
    print('e = {}'.format(private_key.e))
    print('d = {}\n'.format(private_key.d))

    m = random.randint(0, public_key.n)
    print('Исходное сообщение: {}\n'.format(m))

    c = pow(m, public_key.e, public_key.n)
    print('Шифртекст: {}'.format(c))

    attack = AttackKeyLessDecrypt(logs=True)
    m_attacked = attack(public_key, c)

    if m_attacked == m:
        print('Атака прошла успешно')
    else:
        print('Атака прошла безуспешно {} {}'.format(m_attacked, m))


def try_attack_4():
    a, b = 3, 4

    public_key, private_key = rsa.newkeys(16, exponent=5)
    # public_key = rsa.PublicKey(81089, 17)
    # private_key = rsa.PrivateKey(81089, 17, 42533, 131, 619)

    print('Ключ:')
    print('p = {}'.format(private_key.p))
    print('q = {}'.format(private_key.q))
    print('n = {}'.format(private_key.n))
    print('e = {}'.format(private_key.e))
    print('d = {}\n'.format(private_key.d))

    m1 = random.randint(0, public_key.n)
    m2 = (a * m1 + b) % public_key.n

    # m1, m2 = 12345, 12346

    print('Сообщение 1: {}'.format(m1))
    print('Сообщение 2: {}'.format(m2))

    c1 = pow(m1, public_key.e, public_key.n)
    c2 = pow(m2, public_key.e, public_key.n)

    print('Шифртекст 1: {}'.format(c1))
    print('Шифртекст 2: {}'.format(c2))

    attack = AttackTwoAffineMessages(a, b)
    m1_attacked, m2_attacked = attack(public_key, c1, c2)

    if m1_attacked == m1 and m2_attacked == m2:
        print('Атака прошла успешно')
    else:
        print('Атака прошла безуспешно {}, {} -> {}, {}'.format(m1, m2, m1_attacked, m2_attacked))


def generate(bits):
    time_start = time()
    bits >>= 1

    left = 1 << (bits - 1)
    right = (1 << bits) - 1

    # generate p
    p = random.randint(left, right)
    while True:
        if rsa.prime.is_prime(p):
            break
        p += 1
    while True:
        if rsa.prime.is_prime(p) and rsa.prime.is_prime(2 * p + 1):
            break
        p += 2

    sqrt_p = math.sqrt(p)
    p = 2 * p + 1
    print('p = {}'.format(p))

    # generate q
    q = random.randint(left, right)
    while True:
        if rsa.prime.is_prime(q):
            break
        q += 1
    while True:
        if p != q and rsa.prime.is_prime(q) and rsa.prime.is_prime(2 * q + 1):
            break
        q += 2

    # q - prime
    sqrt_q = math.sqrt(q)
    q = 2 * q + 1
    print('q = {}'.format(q))

    assert rsa.prime.is_prime(p)
    assert rsa.prime.is_prime(q)

    n = p * q
    f_n = (p - 1) * (q - 1)

    print('n = {}'.format(n))

    while True:
        # generate e
        while True:
            e = random.randint(1, f_n - 1)
            if math.gcd(e, f_n) == 1:
                break

        d = rsa.common.inverse(e, f_n)
        s = math.sqrt(2) * math.sqrt(sqrt_p) * math.sqrt(sqrt_q)

        if s == math.inf or d > s // 3:
            break

    print('e = {}'.format(e))
    print('d = {}'.format(d))
    print('log(n) = {}'.format(math.log2(n)))

    print('Время: {}'.format(time() - time_start))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--attack', required=False)
    parser.add_argument('--generate', required=False)
    args = parser.parse_args()

    if args.attack == '1':
        try_attack_1()
    elif args.attack == '2':
        try_attack_2()
    elif args.attack == '3':
        try_attack_3()
    elif args.attack == '4':
        try_attack_4()

    if args.generate:
        generate(int(args.generate))
