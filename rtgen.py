"""A simple SHA-1 rainbow table generator."""

import argparse
import base64
import hashlib
import random
import string
import struct

MAXLENGTH = 6
CHARSET = (string.ascii_lowercase + "234567").encode()
TOLOWER = bytes.maketrans(string.ascii_uppercase.encode(),
                          string.ascii_lowercase.encode())


def _sha1(ptext: bytes) -> bytes:
    return hashlib.sha1(ptext).digest()


def _reduction(ctext: bytes) -> bytes:
    return base64.b32encode(ctext).translate(TOLOWER)[:MAXLENGTH]


def _generate(chains: int, length: int, outfile):
    for i in range(chains):
        if (i % 100 == 0):
            print("Generating chain " + str(i))

        # Store the initial password in each chain
        password = bytes(random.sample(CHARSET, MAXLENGTH))
        outfile.write(password)
        outfile.write(b'\n')
        for _ in range(length):
            password = _reduction(_sha1(password))
        outfile.write(password)
        outfile.write(b'\n')


def main():
    """Generate a SHA-1 rainbow table."""

    parser = argparse.ArgumentParser()
    parser.add_argument("chains", type=int,
                        help="the number of chains in the rainbow table")
    parser.add_argument("length", type=int,
                        help="the length of each chain")
    parser.add_argument("outfile", type=str,
                        help="where to write the rainbow table")

    args = parser.parse_args()

    outfile = open(args.outfile, "wb+")
    outfile.write(struct.pack('Q', args.chains))
    outfile.write(struct.pack('Q', args.length))

    _generate(args.chains, args.length, outfile)

    outfile.close()

if __name__ == "__main__":
    main()
