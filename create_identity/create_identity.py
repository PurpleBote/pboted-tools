#!/usr/bin/env python3

__title__ = 'Create Bote Identity'
__version__ = "1.3.2"
__author__ = "polistern"
__maintainer__ = "polistern"
__status__ = "Production"
__license__ = "BSD3"

import base64
import datetime
import sys

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import x25519
from pathlib import Path

ADDRESS_B32_PREFIX = "b32."
ADDRESS_B64_PREFIX = "b64."
DEFAULT_ADDRESS_ENCODE = ADDRESS_B64_PREFIX

ADDRESS_VERSION = b"\x01"
#
ADDRESS_V1_PARAM_LEN = 5
# Crypt
CRYP_TYPE_ECDH256 = b"\x02"  # ECDH256
CRYP_TYPE_ECDH521 = b"\x03"  # ECDH521
CRYP_TYPE_X25519 = b"\x05"  # X25519
CRYP_TYPE_ECDH256_LEN = 33
CRYP_TYPE_ECDH521_LEN = 66
CRYP_TYPE_X25519_LEN = 32
# Sign
SIGN_TYPE_ECDSA256 = b"\x02"  # ECDSA256
SIGN_TYPE_ECDSA521 = b"\x03"  # ECDSA521
SIGN_TYPE_ED25519 = b"\x05"  # ED25519
SIGN_TYPE_ECDSA256_LEN = 33
SIGN_TYPE_ECDSA521_LEN = 66
SIGN_TYPE_ED25519_LEN = 32
# Symm
SYMM_TYPE_AES_256 = b"\x02"  # AES-256
# Hash
HASH_TYPE_SHA_256 = b"\x01"  # SHA-256
HASH_TYPE_SHA_512 = b"\x02"  # SHA-512


IDENTITY_PREFIX = "identity"
PREF_KEY = "key"
PREF_PUBLIC_NAME = "publicName"
PREF_DESCRIPTION = "description"
PREF_SALT = "salt"
PREF_PICTURE = "picture"
PREF_TEXT = "text"
PREF_PUBLISHED = "published"
PREF_DEFAULT = "default"
PREF_CONFIGURATION = "configuration"

IDENTITY_TEMPLATE = {
        PREF_PUBLIC_NAME: '',
        PREF_PUBLISHED: 'false',
        PREF_KEY: '',
        PREF_CONFIGURATION: {
            'includeInGlobalCheck': 'false'
        },
        PREF_DESCRIPTION: '',
        PREF_TEXT: '',
        PREF_PICTURE: '',
        PREF_SALT: ''
    }


def error(message):
    sys.stderr.write(f'ERROR: {message}\n')
    sys.exit(1)


def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def load_identities(filepath, template):
    default_ = ''
    current_identities_ = {}
    loaded_identities_ids_ = []
    identities_names_ = []

    identities_file = Path(filepath)
    if identities_file.is_file():
        identities_file.open()
        identities_lines = identities_file.read_text().splitlines()

        for line in identities_lines:
            if len(line) > 0 and '#' == line[0]:
                continue

            if PREF_DEFAULT in line:
                default_ = line.split('=', 1)[1]

            if IDENTITY_PREFIX in line:
                splitted_line = line.split('.', 1)
                identity_id = int(remove_prefix(splitted_line[0], IDENTITY_PREFIX))

                if identity_id not in loaded_identities_ids_:
                    current_identity = template.copy()
                    loaded_identities_ids_.append(identity_id)
                    current_identities_[f'{identity_id}'] = current_identity

                if len(splitted_line) == 2:
                    key_value = splitted_line[1].split('=', 1)
                    current_identities_[f'{identity_id}'][key_value[0]] = key_value[1]

                    if key_value[0] == PREF_PUBLIC_NAME:
                        identities_names_.append(key_value[1])
                else:
                    if PREF_CONFIGURATION in splitted_line:
                        key_value = splitted_line[2].split('=', 1)
                        current_identities_[f'{identity_id}']['configuration'][key_value[0]] = key_value[1]

    return default_, identities_names_, loaded_identities_ids_, current_identities_


def fill_new_identity(template, args):
    new_identity = template.copy()

    for name in identities_names:
        if args['name'] == name:
            error(f'Identity with name "{name}" already exist in your file {args["path"]}. '
                  f'Try to use different name.')
    new_identity['publicName'] = args['name']

    if args['description']:
        new_identity['description'] = args['description']

    if args['image']:
        with open(args['image'], "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
            new_identity['image'] = encoded_string.decode("utf-8")

    new_identity['key'] = generate_address(int(arguments['algorithm']), int(arguments['format']))

    return new_identity


def get_public_from_full(full_address):
    if ADDRESS_B32_PREFIX not in full_address and ADDRESS_B64_PREFIX not in full_address:
        error("Malformed address")

    full_bytes = bytearray()
    if ADDRESS_B32_PREFIX in full_address:
        full_bytes = base64.b32decode(full_address[len(ADDRESS_B32_PREFIX):], casefold=True)
    if ADDRESS_B64_PREFIX in full_address:
        full_bytes = base64.b64decode(full_address[len(ADDRESS_B64_PREFIX):], altchars=b'-~')

    pub_len = ADDRESS_V1_PARAM_LEN

    if full_bytes[0].to_bytes(length=1, byteorder="big") != ADDRESS_VERSION:
        error('Unsupported address version')

    crypto_type = full_bytes[1].to_bytes(length=1, byteorder="big")
    sign_type = full_bytes[2].to_bytes(length=1, byteorder="big")

    if crypto_type == CRYP_TYPE_ECDH256:
        pub_len += CRYP_TYPE_ECDH256_LEN
    elif crypto_type == CRYP_TYPE_ECDH521:
        pub_len += CRYP_TYPE_ECDH521_LEN
    elif crypto_type == CRYP_TYPE_X25519:
        pub_len += CRYP_TYPE_X25519_LEN
    else:
        error('Unsupported crypto key type')

    if sign_type == SIGN_TYPE_ECDSA256:
        pub_len += SIGN_TYPE_ECDSA256_LEN
    elif sign_type == SIGN_TYPE_ECDSA521:
        pub_len += SIGN_TYPE_ECDSA521_LEN
    elif sign_type == SIGN_TYPE_ED25519:
        pub_len += SIGN_TYPE_ED25519_LEN
    else:
        error('Unsupported signing key type')

    pub_bytes = full_bytes[:pub_len]

    if ADDRESS_B32_PREFIX in full_address:
        return f'{ADDRESS_B32_PREFIX}{base64.b32encode(pub_bytes).decode("utf-8").lower()}'
    if ADDRESS_B64_PREFIX in full_address:
        return f"{ADDRESS_B64_PREFIX}{base64.b64encode(pub_bytes, altchars=b'-~').decode('utf-8')}"


def write_to_file(filepath, identities, default_):
    with open(filepath, 'w') as output:
        output.write(datetime.datetime.utcnow().strftime('# %a %b %d %H:%M:%S UTC %Y\n\n'))
        output.write('# If you need to change default identity - comment current default '
                     'and uncomment one of the follow\n')

        for identity in identities:
            output.write(f'#{identities[identity][PREF_PUBLIC_NAME]}\n')

            pub_key_part_len = 0
            pub_address = ""

            if ADDRESS_B32_PREFIX in identities[identity]["key"] or ADDRESS_B64_PREFIX in identities[identity]["key"]:
                pub_address = get_public_from_full(identities[identity]["key"])
            elif len(identities[identity]["key"]) == 172:
                pub_key_part_len = 86
            elif len(identities[identity]["key"]) == 348:
                pub_key_part_len = 174

            if pub_key_part_len > 0 and len(pub_address) == 0:
                pub_address = identities[identity][PREF_KEY][:pub_key_part_len]
            elif pub_key_part_len == 0 and len(pub_address) > 0:
                pass

            if default_:
                if default_ == pub_address:
                    output.write(f'default={pub_address}\n')
                else:
                    output.write(f'#default={pub_address}\n')
            else:
                default_ = pub_address
                output.write(f'default={pub_address}\n')

        output.write('\n')

        for identity in identities:
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_PUBLIC_NAME}='
                         f'{identities[identity][PREF_PUBLIC_NAME]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_PUBLISHED}='
                         f'{identities[identity][PREF_PUBLISHED]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_KEY}='
                         f'{identities[identity][PREF_KEY]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_CONFIGURATION}.includeInGlobalCheck='
                         f'{identities[identity][PREF_CONFIGURATION]["includeInGlobalCheck"]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_DESCRIPTION}='
                         f'{identities[identity][PREF_DESCRIPTION]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_TEXT}='
                         f'{identities[identity][PREF_TEXT]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_PICTURE}='
                         f'{identities[identity][PREF_PICTURE]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_SALT}='
                         f'{identities[identity][PREF_SALT]}\n\n')


def generate_ecdh_ecdsa_256(version):
    # ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH = 172;
    # ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH = 86;

    cryp_priv_key = ec.generate_private_key(ec.SECP256R1())
    cryp_priv_key_bytes = cryp_priv_key.private_numbers().private_value.to_bytes(CRYP_TYPE_ECDH256_LEN, byteorder='big')
    cryp_pub_key = cryp_priv_key.public_key()
    cryp_pub_key_bytes = cryp_pub_key.public_bytes(encoding=serialization.Encoding.X962,
                                                   format=serialization.PublicFormat.CompressedPoint)

    sign_priv_key = ec.generate_private_key(ec.SECP256R1())
    sign_priv_key_bytes = sign_priv_key.private_numbers().private_value.to_bytes(CRYP_TYPE_ECDH256_LEN, byteorder='big')
    sign_pub_key = sign_priv_key.public_key()
    sign_pub_key_bytes = sign_pub_key.public_bytes(encoding=serialization.Encoding.X962,
                                                         format=serialization.PublicFormat.CompressedPoint)

    if version == 0:
        cryp_priv_key_byte_base_str = base64.b64encode(cryp_priv_key_bytes, altchars=b'-~').decode("utf-8")
        cryp_pub_key_bytes_base_str = base64.b64encode(cryp_pub_key_bytes, altchars=b'-~').decode("utf-8")

        sign_priv_key_byte_base_str = base64.b64encode(sign_priv_key_bytes, altchars=b'-~').decode("utf-8")
        sign_pub_key_bytes_base_str = base64.b64encode(sign_pub_key_bytes, altchars=b'-~').decode("utf-8")

        public_keys = f'{cryp_pub_key_bytes_base_str[1:]}{sign_pub_key_bytes_base_str[1:]}'
        private_keys = f'{cryp_priv_key_byte_base_str[1:]}{sign_priv_key_byte_base_str[1:]}'

        return f'{public_keys}{private_keys}'
    elif version == 1:
        type_part = bytearray(
            ADDRESS_VERSION + CRYP_TYPE_ECDH256 + SIGN_TYPE_ECDSA256 + SYMM_TYPE_AES_256 + HASH_TYPE_SHA_256)

        full_address = type_part + cryp_pub_key_bytes + sign_pub_key_bytes + cryp_priv_key_bytes + sign_priv_key_bytes

        if DEFAULT_ADDRESS_ENCODE == ADDRESS_B32_PREFIX:
            return f'{ADDRESS_B32_PREFIX}{base64.b32encode(full_address).decode("utf-8").lower()}'
        if DEFAULT_ADDRESS_ENCODE == ADDRESS_B64_PREFIX:
            return f"{ADDRESS_B64_PREFIX}{base64.b64encode(full_address, altchars=b'-~').decode('utf-8')}"
    else:
        error('Unsupported address format version')


def generate_ecdh_ecdsa_521(version):
    # ECDH521_ECDSA521_COMPLETE_BASE64_LENGTH = 348;
    # ECDH521_ECDSA521_PUBLIC_BASE64_LENGTH = 174;

    cryp_priv_key = ec.generate_private_key(ec.SECP521R1())
    cryp_priv_key_bytes = cryp_priv_key.private_numbers().private_value.to_bytes(SIGN_TYPE_ECDSA521_LEN, byteorder='big')
    cryp_pub_key = cryp_priv_key.public_key()
    cryp_pub_key_bytes = cryp_pub_key.public_bytes(encoding=serialization.Encoding.X962,
                                                   format=serialization.PublicFormat.CompressedPoint)

    cryp_pub_key_bytes_compress = bytearray(cryp_pub_key_bytes[1:])
    cryp_pub_key_bytes_compress[0] |= (cryp_pub_key_bytes[0] - 2) << 1

    sign_priv_key = ec.generate_private_key(ec.SECP521R1())
    sign_priv_key_bytes = sign_priv_key.private_numbers().private_value.to_bytes(SIGN_TYPE_ECDSA521_LEN, byteorder='big')
    sign_pub_key = sign_priv_key.public_key()
    sign_pub_key_bytes = sign_pub_key.public_bytes(encoding=serialization.Encoding.X962,
                                                   format=serialization.PublicFormat.CompressedPoint)

    if version == 0:
        cryp_priv_key_byte_base_str = base64.b64encode(cryp_priv_key_bytes, altchars=b'-~').decode("utf-8")
        cryp_pub_key_bytes_base_str = base64.b64encode(cryp_pub_key_bytes_compress, altchars=b'-~').decode("utf-8")

        sign_pub_key_bytes_compress = bytearray(sign_pub_key_bytes[1:])
        sign_pub_key_bytes_compress[0] |= (sign_pub_key_bytes[0] - 2) << 1

        sign_priv_key_byte_base_str = base64.b64encode(sign_priv_key_bytes, altchars=b'-~').decode("utf-8")
        sign_pub_key_bytes_base_str = base64.b64encode(sign_pub_key_bytes_compress, altchars=b'-~').decode("utf-8")

        public_keys = f'{cryp_pub_key_bytes_base_str[1:]}{sign_pub_key_bytes_base_str[1:]}'
        private_keys = f'{cryp_priv_key_byte_base_str[1:]}{sign_priv_key_byte_base_str[1:]}'

        return f'{public_keys}{private_keys}'
    elif version == 1:
        type_part = bytearray(
            ADDRESS_VERSION + CRYP_TYPE_ECDH521 + SIGN_TYPE_ECDSA521 + SYMM_TYPE_AES_256 + HASH_TYPE_SHA_512)

        full_address = type_part + cryp_pub_key_bytes_compress + sign_pub_key_bytes + cryp_priv_key_bytes + sign_priv_key_bytes

        if DEFAULT_ADDRESS_ENCODE == ADDRESS_B32_PREFIX:
            return f'{ADDRESS_B32_PREFIX}{base64.b32encode(full_address).decode("utf-8").lower()}'
        if DEFAULT_ADDRESS_ENCODE == ADDRESS_B64_PREFIX:
            return f"{ADDRESS_B64_PREFIX}{base64.b64encode(full_address, altchars=b'-~').decode('utf-8')}"
    else:
        error('Unsupported address format version')


def generate_x25519_ed25519(version):
    # Only new format supported
    if version < 1:
        error('Unsupported address format version')

    cryp_priv_key = x25519.X25519PrivateKey.generate()
    cryp_priv_key_bytes = cryp_priv_key.private_bytes(encoding=serialization.Encoding.Raw,
                                                      format=serialization.PrivateFormat.Raw,
                                                      encryption_algorithm=serialization.NoEncryption())
    cryp_pub_key = cryp_priv_key.public_key()
    cryp_pub_key_bytes = cryp_pub_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                   format=serialization.PublicFormat.Raw)

    sign_priv_key = ed25519.Ed25519PrivateKey.generate()
    sign_priv_key_bytes = sign_priv_key.private_bytes(encoding=serialization.Encoding.Raw,
                                                      format=serialization.PrivateFormat.Raw,
                                                      encryption_algorithm=serialization.NoEncryption())
    sign_pub_key = sign_priv_key.public_key()
    sign_pub_key_bytes = sign_pub_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                   format=serialization.PublicFormat.Raw)

    type_part = bytearray(ADDRESS_VERSION + CRYP_TYPE_X25519 + SIGN_TYPE_ED25519 + SYMM_TYPE_AES_256 + HASH_TYPE_SHA_512)

    full_address = type_part + cryp_pub_key_bytes + sign_pub_key_bytes + cryp_priv_key_bytes + sign_priv_key_bytes

    if DEFAULT_ADDRESS_ENCODE == ADDRESS_B32_PREFIX:
        return f'{ADDRESS_B32_PREFIX}{base64.b32encode(full_address).decode("utf-8").lower()}'
    if DEFAULT_ADDRESS_ENCODE == ADDRESS_B64_PREFIX:
        return f"{ADDRESS_B64_PREFIX}{base64.b64encode(full_address, altchars=b'-~').decode('utf-8')}"


def generate_address(alg, version):
    if alg == 2:
        return generate_ecdh_ecdsa_256(version)
    if alg == 3:
        return generate_ecdh_ecdsa_521(version)
    if alg == 5:
        return generate_x25519_ed25519(version)
    else:
        error('Unsupported algorithm')


if __name__ == '__main__':
    print(f"{__title__} v{__version__}")

    parser = ArgumentParser(
        description=__title__,
        formatter_class=RawDescriptionHelpFormatter
    )

    parser.add_argument('-n', '--name', required=True, help='The public name of the identity, included in emails.')
    parser.add_argument('-f', '--format', choices=[0, 1], help='Address format (default: 1)', default=1, type=int)
    parser.add_argument('-a', '--algorithm', choices=[2, 3, 5], help='Algorithm type (default: 5)', default=5, type=int)
    parser.add_argument('-i', '--image', help='Path to image file')
    parser.add_argument('-d', '--description', help='Description of the identity, only displayed locally.')
    parser.add_argument('-p', '--path', help='Path to identities file (default: identities.txt)', default='identities.txt')

    arguments = vars(parser.parse_args())

    default, identities_names, identities_ids, current_identities = load_identities(arguments['path'], IDENTITY_TEMPLATE)

    if len(identities_ids) > 0:
        current_identities[f'{max(identities_ids) + 1}'] = fill_new_identity(IDENTITY_TEMPLATE, arguments)
    else:
        current_identities[f'{0}'] = fill_new_identity(IDENTITY_TEMPLATE, arguments)

    write_to_file(arguments['path'], current_identities, default)

    exit(0)
