import random
import math
import rsa

import matplotlib.pyplot as plt
import numpy as np


def bits(n):
    """
    Генерирует двоичные разряды n, начиная
    с наименее значимого бита.

    bits(151) -> 1, 1, 1, 0, 1, 0, 0, 1
    """
    while n:
        yield n & 1
        n >>= 1


class EllipticCurvePoint:
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.__curve = curve

    def __str__(self):
        return '({} ; {})'.format(self.x, self.y)

    def clone(self):
        return EllipticCurvePoint(self.x, self.y, self.__curve)

    def __add__(self, other):
        if self.x == other.x:
            m = (3 * self.x ** 2 + self.__curve.a) * rsa.common.inverse(2 * self.y, self.__curve.n)
            m %= self.__curve.n
        else:
            dx = (self.x - other.x) % self.__curve.n
            dy = (self.y - other.y) % self.__curve.n
            m = dy * rsa.common.inverse(dx, self.__curve.n)
            m %= self.__curve.n

        x = (m ** 2 - self.x - other.x) % self.__curve.n
        y = (self.y + m * (x - self.x)) % self.__curve.n
        y = (-y) % self.__curve.n

        return EllipticCurvePoint(x, y, self.__curve).check_curve_exist()

    def __mul__(self, n: int):
        """
        Возвращает результат n * self, вычисленный
        алгоритмом удвоения-сложения.
        """
        Q, P = None, self.clone()

        for bit in bits(n):
            if bit == 1:
                if Q is None:
                    Q = P
                else:
                    Q += P
            P = P + P

        return Q.check_curve_exist()

    def check_curve_exist(self):
        # if pow(self.y, 2, self.__curve.n) != \
               # (pow(self.x, 3, self.__curve.n) + self.__curve.a * self.x + self.__curve.b) % self.__curve.n:
            # print('[WARNING] {} не лежит на кривой {}'.format(self, self.__curve))
            # pass
        return self

    def show(self):
        self.__curve.show(self)


class EllipticCurve:
    def __init__(self, a, b, n):
        self.a = a
        self.b = b
        self.n = n

    def __str__(self):
        return 'y^2 = x^3 {} {}x {} {} (mod {})'.format(
            '+' if self.a >= 0 else '-',
            self.a,
            '+' if self.b >= 0 else '-',
            self.b,
            self.n)

    def __call__(self, x):
        y_2 = (x ** 3 + self.a * x + self.b) % self.n
        Y = []
        for y in range(self.n):
            if pow(y, 2, self.n) == y_2:
                Y.append(y)

        return Y

    @staticmethod
    def generate_curve_and_point(n):
        while True:
            a = random.randint(0, n - 1)
            x = random.randint(0, n - 1)
            y = random.randint(0, n - 1)
            b = (y ** 2 - x ** 3 - a * x) % n

            if (4 * a ** 3 + 27 * b ** 2) % n != 0:
                break

        ec = EllipticCurve(a, b, n)
        point = EllipticCurvePoint(x, y, ec)

        return ec, point

    def show(self, point=None):
        x_space = np.linspace(0, self.n, self.n+1)
        x_show, y_show = [], []
        for x in x_space:
            Y = self(x)
            for y in Y:
                x_show.append(x)
                y_show.append(y)

        plt.scatter(x_show, y_show)
        if point is not None:
            plt.scatter(point.x, point.y, c='black')

        plt.show()
