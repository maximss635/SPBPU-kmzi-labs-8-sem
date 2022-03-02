from elliptic_cryptography import *
from Crypto.Hash import SHA256
import argparse
import rsa.common


class SignParams:
    p = 57896044628890729911196718984933305846544100325488685311213142875135838763683
    q = 28948022314445364955598359492466652923270809441897180344196391207096541510137
    curve = EllipticCurve(1, 51597193811365919768190236681066502033803499635094541650610225403695076439048, p)
    P = EllipticCurvePoint(21371456824977467041033238171905463424508399897529674896678501178686263573482,
                           52962982709744467108853563358242537068648343861092009194618855518747612108192, curve)


class GostModel:
    def __init__(self, params):
        self.__sign_params = params

    def sign_file(self, path, d):
        f = open(path, 'rb')
        data = f.read()
        f.close()

        # print('q = {}'.format(hex(self.__sign_params.q)))

        hash_instance = SHA256.new(data)
        h = hash_instance.digest()
        h = int.from_bytes(h, byteorder='big')
        # print('h = {}'.format(hex(h)))

        e = h % self.__sign_params.q
        if e == 0:
            e = 1
        # print('e = {}'.format(hex(e)))

        while True:
            k = random.randint(1, self.__sign_params.q)
            # print('k = {}'.format(hex(k)))

            C = self.__sign_params.P * k
            r = C.x % self.__sign_params.q
            if r == 0:
                continue

            s = (r * d + k * e) % self.__sign_params.q
            if s == 0:
                continue

            break

        # print('r = {}'.format(hex(r)))
        # print('s = {}'.format(hex(s)))

        return r << 256 | s

    def sign_check(self, path, sign, Q):
        s = sign & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        r = sign >> 256

        # print('s = {}'.format(hex(s)))
        # print('r = {}'.format(hex(r)))

        check = (0 < r < self.__sign_params.q)
        check &= (0 < s < self.__sign_params.q)
        if not check:
            return False

        f = open(path, 'rb')
        data = f.read()
        f.close()

        hash_instance = SHA256.new(data)
        h = hash_instance.digest()
        h = int.from_bytes(h, byteorder='big')
        # print('h = {}'.format(hex(h)))

        e = h % self.__sign_params.q
        if e == 0:
            e = 1
        # print('e = {}'.format(hex(e)))

        v = rsa.common.inverse(e, self.__sign_params.q)
        # print('v = {}'.format(hex(v)))

        z1 = (s * v) % self.__sign_params.q
        z2 = (-r * v) % self.__sign_params.q

        # print('z1 = {}'.format(z1))
        # print('z2 = {}'.format(z2))

        C = self.__sign_params.P * z1 + Q * z2
        # print('C = {}'.format(C))

        R = C.x % self.__sign_params.q
        # print('R = {}'.format(hex(R)))

        return r == R


def forward(model, d, context):
    sign = model.sign_file(context.path, d)
    print('sign = {}'.format(hex(sign)))


def backward(model, Q, context, sign):
    check = model.sign_check(context.path, sign, Q)
    print('check = {}'.format(check))


def main(context):
    params = SignParams()
    model = GostModel(params)

    d = 5719            # private key
    Q = params.P * d    # public key

    # forward(model, d, context)
    backward(model, Q, context, 0x3c6dabf5ffd3a7b155623c7c8773229d79746563e9926e05633eb93106862310aa78bf4b42300ab14e1a9f3c6e7dabd53865422be12f0532163b7ecd7a0e580)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', required=True)

    main(parser.parse_args())
