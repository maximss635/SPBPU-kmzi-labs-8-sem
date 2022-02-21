from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA

from sys import argv

import random
import argparse
import os
import math


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
    type, l = data[0], data[1]
    assert type == 31

    return data[2: 2 + l], data[2 + l:]
