import rsa
import rsa.common
import argparse
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
    print('a')
    private_key_1, private_key_2 = generate_keys_with_common_n(1024)

    attack = AttackCommonModule(private_key_1.n, private_key_1.e, private_key_1.d)
    p_attacked, q_attacked, d_attacked = attack(private_key_2.e)

    if private_key_2.p == p_attacked and private_key_2.q == q_attacked and \
            private_key_2.d == d_attacked:
        print('Атака прошла успешно')
    else:
        print('Атака прошла безуспешно')


def try_attack_2():
    public_key, private_key = rsa.newkeys(128)
    # public_key = rsa.PublicKey(793097, 678271)
    # private_key = rsa.PrivateKey(793097, 678271, 7, 863, 919)

    print('Ключ:')
    print('p = {}'.format(private_key.p))
    print('q = {}'.format(private_key.q))
    print('n = {}'.format(private_key.n))
    print('e = {}'.format(private_key.e))
    print('d = {}'.format(private_key.d))

    attack = VinerAttack()
    private_key_attacked = attack(public_key)

    if private_key.d == private_key_attacked:
        print('Атака прошла успешно')
    else:
        print('Атака прошла безуспешно')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--attack', required=True)
    args = parser.parse_args()

    if args.attack == '1':
        try_attack_1()
    elif args.attack == '2':
        try_attack_2()
