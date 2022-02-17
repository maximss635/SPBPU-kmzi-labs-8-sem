import rsa
import argparse


def main(context):
    (public_key, private_key) = rsa.newkeys(512)

    print('p = {}'.format(private_key.p))
    print('q = {}'.format(private_key.q))

    f = open(context.path_out_public, 'w')
    f.write('e = {}'.format(public_key.e))
    f.write('\n')
    f.write('n = {}'.format(public_key.n))
    f.close()

    f = open(context.path_out_private, 'w')
    f.write('d = {}'.format(private_key.d))
    f.write('\n')
    f.write('n = {}'.format(private_key.n))
    f.close()

    print('Public key: {}'.format(context.path_out_public))
    print('Private key: {}'.format(context.path_out_private))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-out-private', required=True)
    parser.add_argument('--path-out-public', required=True)

    args = parser.parse_args()
    main(args)
