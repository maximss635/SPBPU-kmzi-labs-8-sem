import os.path

import asn1
from Crypto.Hash import SHA256
import argparse

from elliptic_cryptography import *


class SignParams:   # Заполнится из файла
    p = None
    q = None
    curve = None
    P = None


def parse_sign_file(path_sign):
    sign_params = SignParams()

    f = open(path_sign, 'rb')
    data = f.read(os.path.getsize(path_sign))
    f.close()

    decoder = asn1.Decoder()
    decoder.start(data)

    decoder.peek()
    decoder.enter()
    decoder.peek()
    decoder.enter()
    decoder.peek()
    decoder.enter()

    decoder.read(asn1.Numbers.OctetString)
    decoder.read(asn1.Numbers.UTF8String)

    decoder.peek()
    decoder.enter()
    _, x_q = decoder.read(asn1.Numbers.Integer)
    _, y_q = decoder.read(asn1.Numbers.Integer)
    # print('Qx = {}'.format(x_q))
    # print('Qy = {}'.format(y_q))
    decoder.leave()

    decoder.peek()
    decoder.enter()

    decoder.peek()
    decoder.enter()
    _, sign_params.p = decoder.read(asn1.Numbers.Integer)
    # print('p = {}'.format(sign_params.p))
    decoder.leave()

    decoder.peek()
    decoder.enter()
    _, A = decoder.read(asn1.Numbers.Integer)
    _, B = decoder.read(asn1.Numbers.Integer)
    # print('A = {}'.format(A))
    # print('B = {}'.format(B))
    decoder.leave()

    decoder.peek()
    decoder.enter()
    _, x_p = decoder.read(asn1.Numbers.Integer)
    _, y_p = decoder.read(asn1.Numbers.Integer)
    # print('Px = {}'.format(x_p))
    # print('Py = {}'.format(y_p))
    decoder.leave()

    _, sign_params.q = decoder.read(asn1.Numbers.Integer)
    # print('q = {}'.format(sign_params.q))

    decoder.peek()
    decoder.enter()
    _, r = decoder.read(asn1.Numbers.Integer)
    _, s = decoder.read(asn1.Numbers.Integer)

    sign = (r << 256) | s
    # print('r = {}'.format(r))
    # print('s = {}'.format(s))

    decoder.leave()
    decoder.leave()
    decoder.leave()
    decoder.leave()
    decoder.leave()

    sign_params.curve = EllipticCurve(A, B, sign_params.p)
    sign_params.P = EllipticCurvePoint(x_p, y_p, sign_params.curve)
    Q = EllipticCurvePoint(x_q, y_q, sign_params.curve)

    return sign_params, Q, sign


def sign_check(path_file, sign, Q, sign_params):
    print('Проверка:  {}'.format(path_file))

    r = sign & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    s = sign >> 256

    # print('s = {}'.format(hex(s)))
    # print('r = {}'.format(hex(r)))

    check = (0 < r < sign_params.q)
    check &= (0 < s < sign_params.q)
    if not check:
        return False

    f = open(path_file, 'rb')
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
    print('Чтение подписи: {}'.format(context.path_sign))
    sign_params, Q, sign = parse_sign_file(context.path_sign)

    check = sign_check(context.path_file, sign, Q, sign_params)
    if check:
        print('Подпись верная!')
    else:
        print('Подпись неверная!')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-file', required=True)
    parser.add_argument('--path-sign', required=True)

    main(parser.parse_args())

