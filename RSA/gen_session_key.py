import random


if __name__ == '__main__':
    path = 'res/data.key'

    f = open(path, 'wb')
    f.write(random.randbytes(32))
    f.close()

    print('Ключ сгенерирован: {}'.format(path))
