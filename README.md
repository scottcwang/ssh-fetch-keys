# `ssh-fetch-keys`

An `AuthorizedKeysCommand` for `openssh` that retrieves and caches your public keys from online accounts such as GitHub.

## Install

Requires `libcurl`.

```bash
git clone https://github.com/scottcwang/ssh-fetch-keys.git
sudo docker run \
    --rm \
    --interactive \
    --tty \
    --volume $(pwd)/ssh-fetch-keys:/home/rust/src \
    ekidd/rust-musl-builder \
        cargo build --release
sudo install ./ssh-fetch-keys/target/x86_64-unknown-linux-musl/release/ssh-fetch-keys /bin

# root is required because ssh-fetch-keys needs to seteuid to the user who is trying to authenticate
sudo tee /etc/ssh/sshd_config.d/01-authorizedkeyscommand.conf <<EOF
AuthorizedKeysCommand /bin/ssh-fetch-keys %u %k
AuthorizedKeysCommandUser root
EOF

# Add URL templates here. Tokens {1}, {2}, etc. will be replaced by the user-specified parameters to form the request URL
sudo tee /etc/ssh/fetch_keys.conf << EOF
github https://github.com/{1}.keys
EOF

# Make SELinux allow sshd to call ssh-fetch-keys
TEMP_DIR_SELINUX_SSHD=$(mktemp --directory)
sudo tee ${TEMP_DIR_SELINUX_SSHD}/ssh-fetch-keys.te << EOF
module ssh-fetch-keys 1.0;

require {
	type sshd_t;
	type http_port_t;
	class tcp_socket name_connect;
}

allow sshd_t http_port_t:tcp_socket name_connect;
EOF

sudo checkmodule \
    --mls \
    -m \
    --output ${TEMP_DIR_SELINUX_SSHD}/ssh-fetch-keys.mod \
    ${TEMP_DIR_SELINUX_SSHD}/ssh-fetch-keys.te
sudo semodule_package \
    --module ${TEMP_DIR_SELINUX_SSHD}/ssh-fetch-keys.mod \
    --outfile ${TEMP_DIR_SELINUX_SSHD}/ssh-fetch-keys.pp
sudo semodule --install ${TEMP_DIR_SELINUX_SSHD}/ssh-fetch-keys.pp

sudo systemctl restart sshd
```

## Use

Upload your public key to your [GitHub account](https://github.com/settings/keys). Then do the following, replacing `username` with your GitHub username:

```bash
echo "github username" > ~/.ssh/fetch_keys
chmod 644 ~/.ssh/fetch_keys
```

Now authenticate to `ssh` with the corresponding private key.
`sshd` will call `ssh-fetch-keys`, which will retrieve your public keys from `https://github.com/username.keys` and cache them in `~/.ssh/fetch_keys.d/`, for use if GitHub is inaccessible.

## Disclaimer

This software hasn't been reviewed for security: please understand that you use it at your own risk.
