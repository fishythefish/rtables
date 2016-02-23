"""Generate password/hash pairs."""

import argparse
import hashlib
import random
import string

MAXLENGTH = 6
CHARSET = (string.ascii_lowercase + "234567").encode()
TOLOWER = bytes.maketrans(string.ascii_uppercase.encode(),
                          string.ascii_lowercase.encode())


def _sha1(ptext: bytes) -> str:
    return hashlib.sha1(ptext).hexdigest()


def _main():
    parser = argparse.ArgumentParser()
    parser.add_argument("num", type=int,
                        help="how many hashes to generate")
    parser.add_argument("outfile", type=str,
                        help="where to write the hashes")

    args = parser.parse_args()

    outfile = open(args.outfile, "w+")

    for _ in range(args.num):
        password = bytes(random.sample(CHARSET, MAXLENGTH))
        digest = _sha1(password)
        outfile.write(password.decode() + ":" + digest + '\n')

    outfile.close()

if __name__ == "__main__":
    _main()
