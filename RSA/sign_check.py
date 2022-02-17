import os.path

from common import *


def main(context):
    s = from_file(context.path_sign, 64)
    s = int.from_bytes(s, byteorder='big')

    # print('Sign: {}'.format(s))

    text = from_file(context.path_in, os.path.getsize(context.path_in))

    hash_instance = SHA256.new()
    hash_instance.update(text)
    sha256_hash = hash_instance.digest()
    sha256_hash = int.from_bytes(sha256_hash, byteorder='big')

    e, n = parse_rsa_key(context.rsa_key, is_public=True)
    if pow(s, e, n) == sha256_hash:
        print('Подпись верная!')
    else:
        print('Подпись неверная!')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-in', required=True)
    parser.add_argument('--path-sign', required=True)
    parser.add_argument('--rsa-key', required=True)

    args = parser.parse_args()
    main(args)
