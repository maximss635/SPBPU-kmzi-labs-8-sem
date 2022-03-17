from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA

from sys import argv

import random
import argparse
import os
import math

import asn1


RSA_KEY_LEN = 1024


def from_file(path, n):
    f = open(path, 'rb')
    data = f.read(n)
    f.close()

    return data


def parse_rsa_key(path, is_public):
    f = open(path, 'r')
    e_d = f.readline()
    n = f.readline()
    n = int(n.replace('n = ', ''))
    if is_public:
        return int(e_d.replace('e = ', '')), n
    else:
        return int(e_d.replace('d = ', '')), n


def padding_make(data):
    padding = AES.block_size - (len(data) % AES.block_size)
    data = data + (b'0' * padding) + padding.to_bytes(length=AES.block_size, byteorder='big')
    print('Padding: {} bytes of \'0\''.format(padding))

    return data


def padding_remove(data):
    padding = int.from_bytes(data[-AES.block_size:], byteorder='big')
    data = data[:-AES.block_size - padding]
    print('Избавляемся от padding: {} байт'.format(padding))

    return data


def parse_header(data):
    decoder = asn1.Decoder()
    decoder.start(data)

    decoder.peek()
    decoder.enter()

    decoder.peek()
    decoder.enter()

    decoder.peek()
    decoder.enter()

    decoder.peek()
    decoder.read()
    decoder.read()

    decoder.enter()
    _, n = decoder.read()
    _, e = decoder.read()
    decoder.leave()

    decoder.enter()
    _, cipher_key = decoder.read()
    decoder.leave()

    decoder.leave()
    decoder.leave()
    decoder.leave()

    return cipher_key, data[306:]


def make_header(cipher_key, e, n, len_cipher_text):
    if type(cipher_key) != int:
        cipher_key = int.from_bytes(cipher_key, byteorder='big')

    encoder = asn1.Encoder()
    encoder.start()

    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(asn1.Numbers.Set)
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(b'\x00\x01', asn1.Numbers.OctetString)   # RSA
    encoder.write(b'Data', asn1.Numbers.UTF8String)

    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(n, asn1.Numbers.Integer)
    encoder.write(e, asn1.Numbers.Integer)
    encoder.leave()

    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(cipher_key, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()
    encoder.leave()
    encoder.write(b'\x01\x32', asn1.Numbers.OctetString)    # 3DES
    encoder.write(len_cipher_text, asn1.Numbers.Integer)
    encoder.leave()

    header = encoder.output()

    return header
