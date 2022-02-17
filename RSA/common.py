from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from sys import argv

import random
import argparse
import os
import math


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
