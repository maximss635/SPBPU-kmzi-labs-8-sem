from common import *


def main(context):
    data = from_file(context.path_in, os.path.getsize(context.path_in))
    cipher_key, cipher_text = parse_header(data)
    # cipher_key = int.from_bytes(cipher_key, byteorder='big')

    d, n = parse_rsa_key(context.rsa_key, is_public=False)
    key = pow(cipher_key, d, n)
    print('Расшифрованный ключ: {}'.format(hex(key)))

    key = key.to_bytes(32, byteorder='big')

    cipher_instance = AES.new(key, AES.MODE_CBC, iv=b'0000000000000000')
    decrypted_text = cipher_instance.decrypt(cipher_text)

    decrypted_text = padding_remove(decrypted_text)

    path_out = context.path_in + '.decrypted'
    f = open(path_out, 'wb')
    f.write(decrypted_text)
    f.close()

    print('Расшифрованный текст: {}'.format(path_out))
    print('{} bytes -> {} bytes'.format(len(data), len(decrypted_text)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-in', required=True)
    parser.add_argument('--rsa-key', required=True)

    args = parser.parse_args()
    main(args)
