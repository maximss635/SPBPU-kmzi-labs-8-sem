import random
import tkinter

from common import *


def crypt_key(key, e, n):
    k0, k1 = 512, 256
    k = RSA_KEY_LEN

    print('k = {}'.format(k))
    print('k0 = {}'.format(k0))
    print('k1 = {}'.format(k1))

    key <<= k1

    r = random.randbytes(k0 // 8)
    G = SHA512.new()
    H = SHA512.new()

    G.update(r)
    r = G.digest()

    r = int.from_bytes(r, byteorder='big')
    print('r = {}'.format(hex(r)))

    X = r ^ key
    print('X = {}'.format(hex(X)))

    H.update(X.to_bytes(length=(k-k0)//8, byteorder='big'))
    H_X = H.digest()
    H_X = int.from_bytes(H_X, byteorder='big')
    print('H(X) = {}'.format(hex(H_X)))

    Y = r ^ H_X
    print('Y = {}'.format(hex(Y)))

    X_size = (k - k0)
    m1 = (X << X_size) | Y
    print('m = {}'.format(hex(m1)))
    c1 = pow(m1, e, n)

    return c1


def main(context):
    key = from_file(context.data_key, 32)
    print('Ключ: {}'.format(hex(int.from_bytes(key, byteorder='big'))))

    open_text = from_file(context.path_in, os.path.getsize(context.path_in))
    open_text_len = len(open_text)
    open_text = padding_make(open_text)

    cipher_instance = AES.new(key, AES.MODE_CBC, iv=b'0000000000000000')
    cipher_text = cipher_instance.encrypt(open_text)

    key = int.from_bytes(key, byteorder='big')
    e, n = parse_rsa_key(context.rsa_key, is_public=True)

    cipher_key = crypt_key(key, e, n)

    header = make_header(cipher_key, e, n, len(cipher_text))

    print('Header: {} bytes'.format(len(header)))

    path_out = context.path_in + '.encrypted'
    f = open(path_out, 'wb')
    f.write(header)
    f.write(cipher_text)
    f.close()

    print('Файл с шифртекстом: {}'.format(path_out))
    print('{} bytes -> {} bytes'.format(open_text_len, len(cipher_text) + len(header)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-in', required=True)
    parser.add_argument('--rsa-key', required=True)
    parser.add_argument('--data-key', required=True)

    args = parser.parse_args()
    main(args)
