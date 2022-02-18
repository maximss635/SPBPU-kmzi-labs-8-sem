import random
import math
import rsa
from rsa.common import inverse


class AttackCommonModule:
    def __init__(self, n, e, d):
        self.__e_b = e
        self.__d_b = d
        self.__n = n

    def __call__(self, e):
        """
        :return: private_key
        """

        m = self.__e_b * self.__d_b - 1
        print('[Attack] m = {}'.format(m))

        s = m
        while (s & 1) == 0:
            s >>= 1

        print('[Attack] s = {}'.format(s))

        last_b = self.__n - 1
        while last_b == self.__n - 1:
            a = random.randint(0, self.__n)
            print('[Attack] a = {}'.format(a))

            b = pow(a, s, self.__n)

            print('[Attack] wait...')

            while b != 1:
                # print('[Attack] b = {}'.format(b))
                last_b = b
                b = pow(b, 2, self.__n)

        t = last_b
        p, q = math.gcd(t + 1, self.__n), math.gcd(t - 1, self.__n)
        f_n = (p - 1) * (q - 1)

        print('[Attack] p = {}'.format(p))
        print('[Attack] q = {}'.format(q))
        print('[Attack] f(n) = {}'.format(f_n))

        d = inverse(e, f_n)
        print('[Attack] d = {}'.format(d))

        return p, q, d


class VinerAttack:
    def __call__(self, public_key):
        """
        :return:    private_key.d
        """

        m = 100
        print('[Attack] m = {}'.format(m))

        c = pow(m, public_key.e, public_key.n)
        print('[Attack] m^e (mod n) = {}'.format(c))

        frac = self.__to_continued_fraction(public_key.e, public_key.n)
        print('[Attack] e/n = {}'.format(frac))

        Q_, Q__, P_, P__ = 0, 1, 1, 0
        for a in frac:
            print('[Attack] a = {}'.format(a))
            P = a * P_ + P__
            Q = a * Q_ + Q__
            P__, Q__ = P_, Q_
            P_, Q_ = P, Q

            if pow(c, Q, public_key.n) == m:
                return Q

        return None

    @staticmethod
    def __to_continued_fraction(a, b):
        a, q = divmod(a, b)
        t, res = b, [a]

        while q != 0:
            next_t = q
            a, q = divmod(t, q)
            t = next_t
            res.append(a)

        return res
