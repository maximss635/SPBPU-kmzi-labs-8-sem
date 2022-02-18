from common import *


def main(context):
    private_key = RSA.generate(RSA_KEY_LEN)

    print('p = {}'.format(private_key.p))
    print('q = {}'.format(private_key.q))
    print('N = {}'.format(private_key.n))
    print('e = {}'.format(private_key.e))
    print('d = {}'.format(private_key.d))

    f = open(context.path_out_public, 'w')
    f.write('e = {}'.format(private_key.e))
    f.write('\n')
    f.write('n = {}'.format(private_key.n))
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
