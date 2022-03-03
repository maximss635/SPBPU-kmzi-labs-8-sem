from sign_params import *
from sign_params import *

from Crypto.Hash import SHA256
import argparse


def sign_check(path, sign, Q, sign_params):
    s = sign & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    r = sign >> 256

    # print('s = {}'.format(hex(s)))
    # print('r = {}'.format(hex(r)))

    check = (0 < r < sign_params.q)
    check &= (0 < s < sign_params.q)
    if not check:
        return False

    f = open(path, 'rb')
    data = f.read()
    f.close()

    hash_instance = SHA256.new(data)
    h = hash_instance.digest()
    h = int.from_bytes(h, byteorder='big')
    # print('h = {}'.format(hex(h)))

    e = h % sign_params.q
    if e == 0:
        e = 1
    # print('e = {}'.format(hex(e)))

    v = rsa.common.inverse(e, sign_params.q)
    # print('v = {}'.format(hex(v)))

    z1 = (s * v) % sign_params.q
    z2 = (-r * v) % sign_params.q

    # print('z1 = {}'.format(z1))
    # print('z2 = {}'.format(z2))

    C = sign_params.P * z1 + Q * z2
    # print('C = {}'.format(C))

    R = C.x % sign_params.q
    # print('R = {}'.format(hex(R)))

    return r == R


def main(context):
    sign_params = SignParams()
    Q = EllipticCurvePoint(int(context.x), int(context.y), sign_params.curve)

    f = open(context.path_sign, 'rb')
    sign = f.read(64)
    f.close()

    sign = int.from_bytes(sign, byteorder='big')
    print('Подпись: {}'.format(hex(sign)))
    print('Открытый ключ: {}'.format(Q))

    check = sign_check(context.path_file, sign, Q, sign_params)
    if check:
        print('Подпись верная!')
    else:
        print('Подпись неверная!')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-file', required=True)
    parser.add_argument('--x', required=True)
    parser.add_argument('--y', required=True)
    parser.add_argument('--path-sign', required=True)

    main(parser.parse_args())

