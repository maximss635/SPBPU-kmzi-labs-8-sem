from sign_check import *


class SignParams:
    p = 57896044625414088412406986721186632159605151965036429316594800028484330862739
    q = 28948022312707044206203493360593316079803694388568974763893400879284219004579
    curve = EllipticCurve(-1, 53520245325288251180656443226770638951803337703360722011463033447827147086694, p)
    P = EllipticCurvePoint(36066034950041118412594006918367965339490267219250288222432003968962962331642,
                           54906983586985298119491343295734802658016371303757622466870297979342757624191, curve)


def sign_file(path, d, sign_params):
    # print('p = {}'.format(sign_params.p))

    f = open(path, 'rb')
    data = f.read()
    f.close()

    # print('q = {}'.format(hex(sign_params.q)))

    hash_instance = SHA256.new(data)
    h = hash_instance.digest()
    h = int.from_bytes(h, byteorder='big')
    print('Хэщ образ: {}'.format(hex(h)))

    e = h % sign_params.q
    if e == 0:
        e = 1
    # print('e = {}'.format(hex(e)))

    while True:
        k = random.randint(1, sign_params.q)
        # print('k = {}'.format(hex(k)))

        C = sign_params.P * k
        r = C.x % sign_params.q
        if r == 0:
            continue

        s = (r * d + k * e) % sign_params.q
        if s == 0:
            continue

        break

    # print('r = {}'.format(hex(r)))
    # print('s = {}'.format(hex(s)))

    return r << 256 | s


def write_sign_file(path_sign, sign, Q, sign_params):
    encoder = asn1.Encoder()
    encoder.start()

    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(asn1.Numbers.Set)
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(b'\x80\x06\x07\x00', asn1.Numbers.OctetString)   # протокол подписи гост
    encoder.write(b'gostSignKey', asn1.Numbers.UTF8String)

    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(Q.x, asn1.Numbers.Integer)
    encoder.write(Q.y, asn1.Numbers.Integer)
    encoder.leave()

    encoder.enter(asn1.Numbers.Sequence)

    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(sign_params.p, asn1.Numbers.Integer)
    encoder.leave()

    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(sign_params.curve.a, asn1.Numbers.Integer)
    encoder.write(sign_params.curve.b, asn1.Numbers.Integer)
    encoder.leave()

    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(sign_params.P.x, asn1.Numbers.Integer)
    encoder.write(sign_params.P.y, asn1.Numbers.Integer)
    encoder.leave()

    encoder.write(sign_params.q, asn1.Numbers.Integer)

    r = sign & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    s = sign >> 256

    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(r, asn1.Numbers.Integer)
    encoder.write(s, asn1.Numbers.Integer)
    encoder.leave()

    encoder.leave()
    encoder.leave()
    encoder.leave()
    encoder.leave()

    f = open(path_sign, 'wb')
    f.write(encoder.output())
    f.close()


def main(context):
    d = int(context.d)
    sign_params = SignParams()

    sign = sign_file(context.path_file, d, sign_params)

    Q = sign_params.P * d

    write_sign_file(context.path_sign, sign, Q, sign_params)

    print('Файл {} подписан: {}'.format(context.path_file, context.path_sign))
    # assert sign_check(context.path_file, sign, Q, sign_params)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-file', required=True)
    parser.add_argument('--path-sign', required=True)
    parser.add_argument('--d', required=True)

    main(parser.parse_args())
