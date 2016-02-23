"""A simple SHA-1 rainbow table cracker."""

import argparse
import base64
import hashlib
import string
import struct
import typing

BytesList = typing.List[bytes]

MAXLENGTH = 6
TOLOWER = bytes.maketrans(string.ascii_uppercase.encode(),
                          string.ascii_lowercase.encode())


def _sha1(ptext: bytes) -> bytes:
    return hashlib.sha1(ptext).digest()


def _reduction(ctext: bytes) -> bytes:
    return base64.b32encode(ctext).translate(TOLOWER)[:MAXLENGTH]


def _generate_from(start: bytes, rounds: int) -> bytes:
    for _ in range(rounds):
        start = _reduction(_sha1(start))
    return start


def _read_rtable(rtable, chains: int) -> typing.Tuple[BytesList, BytesList]:
    init_passes = []
    final_passes = []

    for _ in range(chains):
        init_passes.append(rtable.readline()[:-1])
        final_passes.append(rtable.readline()[:-1])

    return init_passes, final_passes


def _crack_hash(raw_hash: bytes, length: int,
                starts: BytesList, ends: BytesList):
    candidate = _reduction(raw_hash)
    for k in range(length):
        try:
            i = ends.index(candidate)
            password = _generate_from(starts[i], length - k - 1)
            if _sha1(password) == raw_hash:
                return password
        except ValueError:
            pass
        candidate = _reduction(_sha1(candidate))
    return None


def main():
    """Crack passwords with a SHA-1 rainbow table."""

    parser = argparse.ArgumentParser()
    parser.add_argument("table", type=str,
                        help="the filepath of the rainbow table")
    parser.add_argument("infile", type=str,
                        help="the filepath of the password hashes")
    parser.add_argument("outfile", type=str,
                        help="where to write the cracked passwords")

    args = parser.parse_args()

    rtable = open(args.table, "rb")
    chains = struct.unpack('Q', rtable.read(8))[0]
    length = struct.unpack('Q', rtable.read(8))[0]
    init_passes, final_passes = _read_rtable(rtable, chains)

    infile = open(args.infile, "r")
    outfile = open(args.outfile, "w+", 1)
    for line in infile:
        print("Cracking hash " + line[:-1])
        outfile.write(line[:-1])
        outfile.write(':')
        raw_hash = bytes.fromhex(line[:-1])
        password = _crack_hash(raw_hash, length, init_passes, final_passes)
        if password is not None:
            outfile.write(password.decode())
        outfile.write('\n')

    outfile.close()
    infile.close()
    rtable.close()

if __name__ == "__main__":
    main()
