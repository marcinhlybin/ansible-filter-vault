# Ansible vault filter
# Returns decrypted text from cipher text using secret key file
# Allows to get rid of plain text passwords in ansible repository
# without using ansible-vault and encrypting whole files
#
# Marcin Hlybin, marcin.hlybin@gmail.com
#
from __future__ import print_function
import os
import sys
import argparse
import base64
import getpass
import binascii
from ansible import errors
from ansible.config.manager import ConfigManager, get_ini_config_value
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Section in config file
CONFIG_SECTION = 'vault_filter'

# Read config values
config_manager = ConfigManager()
config_parser = config_manager._parsers.values()[0]

VAULT_FILTER_KEY = get_ini_config_value(config_parser, dict(section=CONFIG_SECTION, key='key')) or 'vault.key'
VAULT_FILTER_SALT = get_ini_config_value(config_parser, dict(section=CONFIG_SECTION, key='salt')) or None
VAULT_FILTER_ITERATIONS = get_ini_config_value(config_parser, dict(section=CONFIG_SECTION, key='iterations')) or 1000000
VAULT_FILTER_GENERATE_KEY = get_ini_config_value(config_parser, dict(section=CONFIG_SECTION, key='generate_key')) or False
DEFAULT_VAULT_PASSWORD_FILE = config_manager.data.get_setting('DEFAULT_VAULT_PASSWORD_FILE').value

# Read environment variables
VAULT_FILTER_KEY = os.getenv('VAULT_FILTER_KEY', VAULT_FILTER_KEY)
VAULT_FILTER_SALT = os.getenv('VAULT_FILTER_SALT', VAULT_FILTER_SALT)
VAULT_FILTER_ITERATIONS = os.getenv('VAULT_FILTER_ITERATIONS', VAULT_FILTER_ITERATIONS)
VAULT_FILTER_GENERATE_KEY = os.getenv('VAULT_FILTER_GENERATE_KEY', VAULT_FILTER_GENERATE_KEY)

VAULT_FILTER_KEY = os.path.abspath(VAULT_FILTER_KEY)
verbose = True

def vault(cipher):
    try:
        f = fernet()
        return f.decrypt(bytes(cipher))
    except IOError:
        raise errors.AnsibleFilterError("vault: could not open key file: {}. Please run 'vault.py' filter file with --key option first.".format(VAULT_FILTER_KEY))
    except InvalidToken:
        raise errors.AnsibleFilterError("vault: could not decrypt variable. Invalid vault key.")
    except ValueError:
        raise errors.AnsibleFilterError("vault: variable vault_filter_salt is not defined in ansible config")
    except:
        raise errors.AnsibleFilterError('vault: unknown error: {} {}'.format(sys.exc_type, sys.exc_value))

def fernet():
    if not os.path.isfile(VAULT_FILTER_KEY) and VAULT_FILTER_GENERATE_KEY and DEFAULT_VAULT_PASSWORD_FILE:
        global verbose
        verbose = False
        vault_key()

    with open(VAULT_FILTER_KEY, 'rb') as f:
        key = f.read().rstrip()
        return Fernet(key)

def vault_key():
    if not VAULT_FILTER_SALT:
        raise ValueError("Variable 'vault_filter_salt' is not set in ansible.cfg file. Please generate salt with '--salt' option.")

    if os.path.isfile(VAULT_FILTER_KEY):
        raise IOError("Vault filter key '{}' already exists. Remove it first to generate new one.".format(VAULT_FILTER_KEY))

    if verbose:
        print("Vault filer key '{}' not found".format(VAULT_FILTER_KEY))

    if DEFAULT_VAULT_PASSWORD_FILE:
        if verbose:
            print("Generating vault filter key from ansible vault password file")
        with open(DEFAULT_VAULT_PASSWORD_FILE, 'rb') as f:
            vault_password = f.read().rstrip()
    else:
        print("Generating vault filter key with user provided password")
        vault_password = getpass.getpass('Key password: ')
        if len(vault_password) < 8:
            raise ValueError("Key password too short (>= 8)")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=bytes(VAULT_FILTER_SALT),
        iterations=int(VAULT_FILTER_ITERATIONS),
        backend=default_backend()
    )
    vault_key = base64.urlsafe_b64encode(kdf.derive(vault_password))

    with open(VAULT_FILTER_KEY, 'wb') as f:
        os.chmod(VAULT_FILTER_KEY, 0o600)
        f.write(vault_key + '\n')

class FilterModule(object):
    def filters(self):
        return {
            'vault': vault
        }

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--salt', action='store_true', help='generate random vault filter salt for ansible.cfg config')
    parser.add_argument('-k', '--key', action='store_true', help='generate secret key from password prompt or using ansible vault password')
    parser.add_argument('-e', '--encrypt', metavar='TEXT', action='store', help='encrypt string from plain text')
    parser.add_argument('-d', '--decrypt', metavar='CRYPT', action='store', help='decrypt string from cipher text')
    parser.add_argument('-q', '--quiet', action='store_true', help='do not output info messages')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    if args.quiet: verbose=False

    try:
        if args.key:
            vault_key()
        elif args.salt:
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(os.urandom(32))
            print("Save following line to ansible.cfg config file under [{}]:".format(SECTION))
            print("vault_filter_salt = {}".format(binascii.b2a_hex(digest.finalize())))
        elif args.encrypt:
            f = fernet()
            print(f.encrypt(args.encrypt))
        elif args.decrypt:
            f = fernet()
            print(f.decrypt(args.decrypt))
    except InvalidToken:
        print('ERROR: Could not decrypt with following vault key: {}'.format(VAULT_FILTER_KEY))
        sys.exit(1)
    except:
        print('ERROR: ' + str(sys.exc_value))
        sys.exit(1)
