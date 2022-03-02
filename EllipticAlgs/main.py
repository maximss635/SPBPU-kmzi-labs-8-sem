import argparse
import time

import matplotlib.pyplot as plt
import rsa.prime

from elliptic_cryptography import *


def prime_generator(n):
    yield 2
    yield 3

    p, i = 5, n - 2
    while True:
        if rsa.prime.is_prime(p):
            i -= 1
            yield p
        p += 2
        if i == 0:
            break


def algorythm(n, m):
    print('n = {}'.format(n))
    print('m = {}'.format(m))

    while True:
        # Генерируем эллиптическую кривую и точку на ней

        ec, Q = EllipticCurve.generate_curve_and_point(n)
        # ec = EllipticCurve(-1, 3231, n)
        # Q = EllipticCurvePoint(87, 2, ec)

        print('Кривая: {}'.format(ec))
        print('Точка: Q = {}'.format(Q))

        for i, p in enumerate(prime_generator(m)):
            a = int(math.log2(n) / math.log2(p) / 2)

            # print('Q *= {}^{}'.format(p, a))
            try:
                for j in range(a):
                    Q *= p
            except rsa.common.NotRelativePrimeError as ex:
                return ex.d


def main(context):
    n = int(context.number)
    m = int(context.base)

    if rsa.prime.is_prime(n):
        print('{} - простое'.format(n))
        return

    p = algorythm(n, m)
    if (p is not None) and (n % p == 0) and p != n:
        q = n // p

        print('Успешно!')
        print('p = {}'.format(p))
        print('q = {}'.format(q))
    else:
        print('Безуспешно')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--number', required=True)
    parser.add_argument('--base', required=True)

    args = parser.parse_args()

    main(args)
