import argparse
import rsa.prime
import threading
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


class Attack(threading.Thread):
    def __init__(self, n, m, on_done, on_iter):
        super().__init__()
        self.__n = n
        self.__m = m
        self.__on_done = on_done
        self.__on_iter = on_iter

    def run(self):
        if rsa.prime.is_prime(self.__n):
            return self.__on_done(self.__n, None)

        print('n = {}'.format(self.__n))
        print('m = {}'.format(self.__m))

        while True:
            # Генерируем эллиптическую кривую и точку на ней

            ec, Q = EllipticCurve.generate_curve_and_point(self.__n)
            # ec = EllipticCurve(-1, 3231, n)
            # Q = EllipticCurvePoint(87, 2, ec)

            self.__on_iter(ec, Q)

            for i, p in enumerate(prime_generator(self.__m)):
                a = int(math.log2(self.__n) / math.log2(p) / 2)
                try:
                    for j in range(a):
                        Q *= p
                except rsa.common.NotRelativePrimeError as ex:
                    self.__on_done(self.__n, ex.d)
                    return


def report(n, p):
    if (p is not None) and (n % p == 0) and p != n:
        q = n // p

        print('Успешно!')
        print('p = {}'.format(p))
        print('q = {}'.format(q))
    else:
        print('Безуспешно')


def iter(ec, Q):
    print('Кривая: {}'.format(ec))
    print('Точка: Q = {}\n'.format(Q))


def main(context):
    n = int(context.number)
    m = int(context.base)

    attack = Attack(n, m, on_done=report, on_iter=iter)
    attack.start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--number', required=True)
    parser.add_argument('--base', required=True)

    args = parser.parse_args()

    main(args)
