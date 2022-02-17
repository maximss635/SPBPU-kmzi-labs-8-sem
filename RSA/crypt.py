from common import *


def main(context):
    key = from_file(context.data_key, 32)
    print('Ключ: {}'.format(int.from_bytes(key, byteorder='big')))

    open_text = from_file(context.path_in, os.path.getsize(context.path_in))

    if len(open_text) % 16 != 0:
        print('Padding: {} bytes'.format(len(open_text) % 16))
        open_text = open_text + (b'0' * (len(open_text) % 16))

    cipher_instance = AES.new(key, AES.MODE_CBC, iv=b'0000000000000000')
    cipher_text = cipher_instance.encrypt(open_text)

    key = int.from_bytes(key, byteorder='big')
    e, n = parse_rsa_key(context.rsa_key, is_public=True)

    cipher_key = pow(key, e, n)
    cipher_key = cipher_key.to_bytes(length=64, byteorder='big')

    l, type = 64, 31
    header = type.to_bytes(1, 'big') + l.to_bytes(1, 'big') + cipher_key

    print('Header: {}'.format(header))

    path_out = context.path_in.replace('.in', '.out')
    f = open(path_out, 'wb')
    f.write(header)
    f.write(cipher_text)
    f.close()

    print('Файл с шифртекстом: {}'.format(path_out))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-in', required=True)
    parser.add_argument('--rsa-key', required=True)
    parser.add_argument('--data-key', required=True)

    args = parser.parse_args()
    main(args)
