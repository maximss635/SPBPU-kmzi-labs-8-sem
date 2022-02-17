from common import *


def parse_header(data):
    type, l = data[0], data[1]
    assert type == 31

    return data[2: 2 + l], data[2 + l:]


def main(context):
    data = from_file(context.path_in, os.path.getsize(context.path_in))
    cipher_key, cipher_text = parse_header(data)
    cipher_key = int.from_bytes(cipher_key, byteorder='big')

    d, n = parse_rsa_key(context.rsa_key, is_public=False)
    key = pow(cipher_key, d, n)
    print('Расшифрованный ключ: {}'.format(key))

    key = key.to_bytes(32, byteorder='big')

    cipher_instance = AES.new(key, AES.MODE_CBC, iv=b'0000000000000000')
    decrypted_text = cipher_instance.decrypt(cipher_text)

    path_out = context.path_in.replace('.out', '.out.decrypted')
    f = open(path_out, 'wb')
    f.write(decrypted_text)
    f.close()

    print('Расшифрованный текст: {}'.format(path_out))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-in', required=True)
    parser.add_argument('--rsa-key', required=True)

    args = parser.parse_args()
    main(args)
