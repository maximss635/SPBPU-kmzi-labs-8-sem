import os.path

from common import *


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

    cipher_key = pow(key, e, n)
    # print('Зашифрованный ключ: {}'.format(hex(cipher_key)))
    cipher_key = cipher_key.to_bytes(RSA_KEY_LEN//8, byteorder='big')

    header = make_header(cipher_key, e, n)

    print('Header: {} bytes'.format(len(header)))

    path_out = context.path_in + '.encrypted'
    f = open(path_out, 'wb')
    f.write(header)
    f.write(cipher_text)
    f.close()

    # print('Шифртекст {}'.format(cipher_text))

    print('Файл с шифртекстом: {}'.format(path_out))
    print('{} bytes -> {} bytes'.format(open_text_len, len(cipher_text) + len(header)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-in', required=True)
    parser.add_argument('--rsa-key', required=True)
    parser.add_argument('--data-key', required=True)

    args = parser.parse_args()
    main(args)
