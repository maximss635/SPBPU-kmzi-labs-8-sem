import random
import argparse


def main(context):
    f = open(context.path_out, 'wb')
    f.write(random.randbytes(32))
    f.close()

    print('Ключ сгенерирован: {}'.format(context.path_out))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-out', required=True)

    args = parser.parse_args()
    main(args)
