from common import *


def main(context):
    text = from_file(context.path_in, os.path.getsize(context.path_in))

    hash_instance = SHA256.new()
    hash_instance.update(text)

    sha256_hash = hash_instance.digest()
    sha256_hash = int.from_bytes(sha256_hash, byteorder='big')

    print('SHA-256 hash sum: {}'.format(sha256_hash))

    d, n = parse_rsa_key(context.rsa_key, is_public=False)
    s = pow(sha256_hash, d, n)

    print('Sign: {}'.format(s))

    s = s.to_bytes(RSA_KEY_LEN//8, byteorder='big')
    path_sign = context.path_in + '.sign'
    f = open(path_sign, 'wb')
    f.write(s)
    f.close()

    print('Sign saved to: {}'.format(path_sign))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-in', required=True)
    parser.add_argument('--rsa-key', required=True)

    args = parser.parse_args()
    main(args)
