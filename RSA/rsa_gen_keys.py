import rsa


if __name__ == '__main__':
    (public_key, private_key) = rsa.newkeys(512)

    print('p = {}'.format(private_key.p))
    print('q = {}'.format(private_key.q))

    f = open('res/rsa_public.key', 'w')
    f.write('e = {}'.format(public_key.e))
    f.write('\n')
    f.write('n = {}'.format(public_key.n))
    f.close()

    f = open('res/rsa_private.key', 'w')
    f.write('d = {}'.format(private_key.d))
    f.write('\n')
    f.write('n = {}'.format(private_key.n))
    f.close()

    print('Public key: {}'.format('res/rsa_public.key'))
    print('Private key: {}'.format('res/rsa_private.key'))
