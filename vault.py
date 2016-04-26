from __future__ import print_function
# Ansible vault filter
# Returns decrypted text from cipher text using secret key file
# Allows to get rid of plain text passwords in ansible repository
# without using ansible-vault and encrypting whole files
#
# Marcin Hlybin, marcin.hlybin@gmail.com
#
import os
import sys
import argparse
import base64
import getpass
import binascii
import ansible.constants as C
from ansible import errors
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# section in config file
FILTERS = 'filters'

VAULT_FILTER_KEY = C.get_config(C.p, FILTERS, 'vault_filter_key', 'ANSIBLE_VAULT_FILTER_KEY', 'vault.key', ispath=True)
VAULT_FILTER_SALT = C.get_config(C.p, FILTERS, 'vault_filter_salt', 'ANSIBLE_VAULT_FILTER_SALT', None)
VAULT_FILTER_ITERATIONS = C.get_config(C.p, FILTERS, 'vault_filter_iterations', 'ANSIBLE_VAULT_FILTER_ITERATIONS', 1000000, integer=True)
VAULT_FILTER_GENERATE_KEY = C.get_config(C.p, FILTERS, 'vault_filter_generate_key', 'ANSIBLE_VAULT_GENERATE_KEY', False, boolean=True)

vault_filter_key = os.path.abspath(VAULT_FILTER_KEY)
verbose = True

def vault(cipher):
    try:
        f = fernet()
        return f.decrypt(bytes(cipher))
    except IOError:
        raise errors.AnsibleFilterError("vault: could not open key file: {}. Please run 'vault.py' filter file with --key option first.".format(vault_filter_key))
    except InvalidToken:
        raise errors.AnsibleFilterError("vault: could not decrypt variable. Invalid vault key.")
    except ValueError:
        raise errors.AnsibleFilterError("vault: variable vault_filter_salt is not defined in ansible config")
    except:
        raise errors.AnsibleFilterError('vault: unknown error: {} {}'.format(sys.exc_type, sys.exc_value))

def fernet():
    if not os.path.isfile(vault_filter_key) and VAULT_FILTER_GENERATE_KEY and C.DEFAULT_VAULT_PASSWORD_FILE:
        global verbose
        verbose = False
        vault_key()

    with open(vault_filter_key, 'rb') as f:
        key = f.read().rstrip()
        return Fernet(key)

def vault_key():
    if not VAULT_FILTER_SALT:
        raise ValueError("Variable 'vault_filter_salt' is not set in ansible.cfg file. Please generate salt with '--salt' option.")

    if os.path.isfile(vault_filter_key):
        raise IOError("Vault filter key '{}' already exists. Remove it first to generate new one.".format(vault_filter_key))

    if verbose: print("Vault filer key '{}' not found".format(vault_filter_key))
    if C.DEFAULT_VAULT_PASSWORD_FILE:
        if verbose: print("Generating vault filter key from ansible vault password file")
        with open(C.DEFAULT_VAULT_PASSWORD_FILE, 'rb') as f:
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
        iterations=VAULT_FILTER_ITERATIONS,
        backend=default_backend()
    )
    vault_key = base64.urlsafe_b64encode(kdf.derive(vault_password))

    with open(vault_filter_key, 'wb') as f:
        os.chmod(vault_filter_key, 0o600)
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
            print("Save following line to ansible.cfg config file under [{}]:".format(FILTERS))
            print("vault_filter_salt = {}".format(binascii.b2a_hex(digest.finalize())))
        elif args.encrypt:
            f = fernet()
            print(f.encrypt(args.encrypt))
        elif args.decrypt:
            f = fernet()
            print(f.decrypt(args.decrypt))
    except:
        print('ERROR: ' + str(sys.exc_value))
        sys.exit(1)
