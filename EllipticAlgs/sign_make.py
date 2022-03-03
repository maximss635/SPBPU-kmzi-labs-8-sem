from sign_check import *
from sign_params import *

from Crypto.Hash import SHA256
import argparse


def sign_file(path, d, sign_params):
    f = open(path, 'rb')
    data = f.read()
    f.close()

    # print('q = {}'.format(hex(self.__sign_params.q)))

    hash_instance = SHA256.new(data)
    h = hash_instance.digest()
    h = int.from_bytes(h, byteorder='big')
    # print('h = {}'.format(hex(h)))

    e = h % sign_params.q
    if e == 0:
        e = 1
    # print('e = {}'.format(hex(e)))

    while True:
        k = random.randint(1, sign_params.q)
        # print('k = {}'.format(hex(k)))

        C = sign_params.P * k
        r = C.x % sign_params.q
        if r == 0:
            continue

        s = (r * d + k * e) % sign_params.q
        if s == 0:
            continue

        break

    # print('r = {}'.format(hex(r)))
    # print('s = {}'.format(hex(s)))

    return r << 256 | s


def main(context):
    d = int(context.d)
    sign_params = SignParams()

    sign = sign_file(context.path_file, d, sign_params)

    path_sign = context.path_file + '.sign'
    f = open(path_sign, 'wb')
    f.write(sign.to_bytes(byteorder='big', length=64))
    f.close()

    Q = sign_params.P * d

    print('Подпись: {}'.format(path_sign))
    print('Открытый ключ (для проверки): {}'.format(Q))

    assert sign_check(context.path_file, sign, Q, sign_params)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-file', required=True)
    parser.add_argument('--d', required=True)

    main(parser.parse_args())
