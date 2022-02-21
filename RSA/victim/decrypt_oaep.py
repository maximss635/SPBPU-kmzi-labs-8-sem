from common import *


def decrypt_key(cipher_key, d, n):
    k0, k1 = 512, 256
    k = RSA_KEY_LEN

    m1 = pow(cipher_key, d, n)
    print('m = {}'.format(hex(m1)))

    X_size = (k - k0)
    H = SHA512.new()
    G = SHA512.new()

    X = m1 >> X_size
    Y = m1 & ((1<<X_size)-1)
    H.update(X.to_bytes(byteorder='big', length=X_size//8))
    H_X = int.from_bytes(H.digest(), byteorder='big')

    print('X = {}'.format(hex(X)))
    print('Y = {}'.format(hex(Y)))
    print('H(X) = {}'.format(hex(H_X)))

    r = Y ^ H_X
    print('r = {}'.format(hex(r)))

    G.update(r.to_bytes(byteorder='big', length=k0//8))

    m = X ^ r

    print('m = {}'.format(hex(m)))
    m >>= k1
    print('m = {}'.format(hex(m)))

    return m


def main(context):
    data = from_file(context.path_in, os.path.getsize(context.path_in))
    cipher_key, cipher_text = parse_header(data)
    cipher_key = int.from_bytes(cipher_key, byteorder='big')

    d, n = parse_rsa_key(context.rsa_key, is_public=False)
    key = decrypt_key(cipher_key, d, n)
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
