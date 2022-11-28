#!/usr/bin/env python3

import argparse
import codecs
import os
import sys


def scramble_message(message):
    return codecs.encode(message, "rot_13")


def unscramble_message(message):
    return codecs.decode(message.decode(), "rot_13")


def encrypt(file, message):
    with open(file, "r+") as f:
        f.seek(0x8)
        f.write(scramble_message(message))


def decrypt(file):
    with open(file, "rb") as f:
        f.seek(0x08)
        message = f.read(0x8)
        cleartext = unscramble_message(message)
        print("[!] decrypting padding bytes of {}: {}".format(file, cleartext))


def decrypt_folder(path):
    os.chdir(path)
    for file in sorted(os.listdir(path)):
        with open(file, "rb") as f:
            f.seek(0x08)
            message = f.read(0x8)
            cleartext = unscramble_message(message)
            print("[!] decrypting padding bytes of {}: {}".format(file, cleartext))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--encrypt", help="encrypt in elf file")
    parser.add_argument("-m", "--message", help="8 bit message to encrypt")
    parser.add_argument("-d", "--decrypt", help="decrypt from path with elf files")
    args = parser.parse_args()
    if args.decrypt and not args.encrypt and not args.message:
        decrypt_folder(args.decrypt)
    elif args.encrypt and not args.message:
        print("Usage: python3 elf_crypter.py --encrypt ELF_BINARY -m MESSAGE")
    elif not args.decrypt and not args.encrypt and not args.message:
        print("Usage: python3 elf_crypter.py --encrypt/--decrypt ELF_BINARY")
    else:
        encrypt(args.encrypt, args.message)


if __name__ == "__main__":
    sys.exit(main())
