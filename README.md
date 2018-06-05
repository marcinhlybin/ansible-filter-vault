# Ansible vault filter

Returns decrypted text from cipher text using secret key file. Allows to get rid of plain text passwords in ansible repository without using `ansible-vault` nor encrypting whole files.

This release works with Ansible 2.5+

## Configuration

Configuration options in `ansible.cfg`. Please notice section name `vault_filter`:

```
[vault_filter]
key = vault.key # might be relative or absolute path
salt = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 # generate random salt with '--salt' option
iterations = 1000000 # PBKDF2-SHA512 iterations
generate_key = yes # automatically generate vault key during playbook runtime

[defaults]
vault_password_file = vault.pass # this is from ansible-vault, if specified vault filter will use this password to generate vault filter key
```

## Usage

1. generate random salt and put it to ansible.cfg file  
  `python filter_plugins/vault.py --salt`

1. generate key file (you will be asked for password if vault_password_file is not defined)  
    `python filter_plugins/vault.py --key`

1. encrypt password to be used in hostvar  
    `python filter_plugins/vault.py --encrypt my_secret_password_to_database`

1. store encrypted password in hostvars  
```
vars:  
  db_password: {{ 'gAAAAABWasKsAvkyCqmc_8p57vGHOHkAG4nU4vo8t6n6C-j3hItbiwC1BRLnrHBJtrDP1Rz2wG1HULRG_zkXF596H0dn-69S92Ky3ixDOCAGesFptH1-glQ=' | vault }}
```
1. when needed you may decrypt password  
    `python filter_plugins/vault.py --decrypt gAAAAABWasKsAvkyCqmc_8p57vGHOHkAG4nU4vo8t6n6C-j3hItbiwC1BRLnrHBJtrDP1Rz2wG1HULRG_zkXF596H0dn-69S92Ky3ixDOCAGesFptH1-glQ=`

If you set you set `vault_filter_generate_key = yes` and `vault_password_file` option is present and vault filter salt is defined in `ansible.cfg`, vault key file will be generated automatically without any message while playbook is running. This option can be useful with Ansible Tower. It might be a good idea to remove vault key in post_tasks in your playbook.

### Example variable formats in hostvars

```
password_crypt: gAAAAABWasKsAvkyCqmc_8p57vGHOHkAG4nU4vo8t6n6C-j3hItbiwC1BRLnrHBJtrDP1Rz2wG1HULRG_zkXF596H0dn-69S92Ky3ixDOCAGesFptH1-glQ=  
password_plain: "{{ password_crypt | vault }}"  
password: "{{ 'gAAAAABWasKsAvkyCqmc_8p57vGHOHkAG4nU4vo8t6n6C-j3hItbiwC1BRLnrHBJtrDP1Rz2wG1HULRG_zkXF596H0dn-69S92Ky3ixDOCAGesFptH1-glQ=' | vault }}"
```

## Repository

It is completely safe to keep salt value in `ansible.cfg`. You can push it to your repository.
It is **NOT** safe to keep vault key in repository! Add it to `.gitignore`
