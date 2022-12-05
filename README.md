# authorized-keys

Configuration file based management of SSH authorized keys, via SSH.

## Usage

### CLI

```sh
authorized-keys --help
```

```
Usage: authorized-keys --config <CONFIG> <COMMAND>

Commands:
  push   Push the authorized keys defined in the configuration file
  pull   Pull the authorized keys into the configuration file
  audit  Audit the authorized keys stored on remote servers
  help   Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>  Path to the YAML configuration file
  -h, --help             Print help information
```

### Configuration file

```yaml
hosts:
  example.com:
  - user: test
    path: /home/test/.ssh/authorized_keys
    authorized_keys:
    - '@deploy-bot'
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCd... user@host
  bastion.my:
  - user: root
    path: /root/.ssh/authorized_keys
    authorized_keys:
    - '@deploy-bot'
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCf...
  - user: root
    path: /home/foo/.ssh/authorized_keys
    authorized_keys:
    - '@deploy-bot'
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCa...
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCb...
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCc...
  - user: root
    path: /home/bar/.ssh/authorized_keys
    authorized_keys: []
identities:
  deploy-bot:
  - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2...
```
