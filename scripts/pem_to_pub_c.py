#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2015, Linaro Limited


def get_args():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--prefix', required=True,
        help='Prefix for the public key exponent and modulus in c file')
    parser.add_argument(
        '--out', required=True,
        help='Name of c file for the public key')
    parser.add_argument('--key', required=True, help='Name of key file')

    return parser.parse_args()


def main():
    import array
    import os
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    args = get_args()

    with open(args.key, 'rb') as f:
        data = f.read()

    # Resolve text link stubs (for example "Link: default.pem" produced when
    # symlinks are checked out as regular files on some setups).
    key_ref = None
    for encoding in ('utf-8-sig', 'utf-16', 'utf-16-le'):
        try:
            text = data.decode(encoding).strip()
        except UnicodeDecodeError:
            continue

        if text.startswith('Link:'):
            key_ref = text.split(':', 1)[1].strip()
            break
        if text and not any(c.isspace() for c in text) and \
                not text.startswith('-----BEGIN'):
            key_ref = text
            break

    if key_ref:
        key_ref_path = os.path.join(os.path.dirname(args.key), key_ref)
        if not os.path.isfile(key_ref_path):
            raise ValueError("Key link target '{}' not found"
                             .format(key_ref_path))
        with open(key_ref_path, 'rb') as f:
            data = f.read()

    errors = []
    key = None
    loaders = (
        lambda d: serialization.load_pem_private_key(
            d, password=None, backend=default_backend()).public_key(),
        lambda d: serialization.load_pem_public_key(
            d, backend=default_backend()),
        lambda d: serialization.load_ssh_private_key(
            d, password=None, backend=default_backend()).public_key(),
        lambda d: serialization.load_ssh_public_key(
            d, backend=default_backend()),
    )
    for load_key in loaders:
        try:
            key = load_key(data)
            break
        except (ValueError, TypeError, UnsupportedAlgorithm) as ex:
            errors.append(ex)

    if key is None:
        raise ValueError(
            "Could not load key '{}' as PEM/OpenSSH public or private key"
            .format(args.key)) from errors[-1]
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Key '{}' is not an RSA key".format(args.key))

    # Refuse public exponent with more than 32 bits. Otherwise the C
    # compiler may simply truncate the value and proceed.
    # This will lead to TAs seemingly having invalid signatures with a
    # possible security issue for any e = k*2^32 + 1 (for any integer k).
    if key.public_numbers().e > 0xffffffff:
        raise ValueError(
            'Unsupported large public exponent detected. ' +
            'OP-TEE handles only public exponents up to 2^32 - 1.')

    with open(args.out, 'w') as f:
        f.write("#include <stdint.h>\n")
        f.write("#include <stddef.h>\n\n")
        f.write("const uint32_t " + args.prefix + "_exponent = " +
                str(key.public_numbers().e) + ";\n\n")
        f.write("const uint8_t " + args.prefix + "_modulus[] = {\n")
        i = 0
        nbuf = key.public_numbers().n.to_bytes(key.key_size >> 3, 'big')
        for x in array.array("B", nbuf):
            f.write("0x" + '{0:02x}'.format(x) + ",")
            i = i + 1
            if i % 8 == 0:
                f.write("\n")
            else:
                f.write(" ")
        f.write("};\n")
        f.write("const size_t " + args.prefix + "_modulus_size = sizeof(" +
                args.prefix + "_modulus);\n")


if __name__ == "__main__":
    main()
