# authorized-keys

Configuration based management of SSH authorized keys.

## Usage

### CLI

```sh
authorized-keys --help
```

```
Usage: authorized-keys --config <CONFIG> <COMMAND>

Commands:
  push  Push the authorized keys defined in the configuration file
  pull  Pull the authorized keys into the configuration file
  help  Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>
  -h, --help             Print help information
```

### Configuration file

```yaml
hosts:
  example.com:
  - user: test
    path: /home/test/.ssh/authorized_keys
    authorized_keys:
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCd... user@host
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2...
  bastion.my:
  - user: root
    path: /root/.ssh/authorized_keys
    authorized_keys:
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCf...
  - user: root
    path: /home/foo/.ssh/authorized_keys
    authorized_keys:
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCa...
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCb...
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCc...
  - user: root
    path: /home/bar/.ssh/authorized_keys
    authorized_keys: []
```
