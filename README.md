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
    ekidd/rust-musl-builder:z \
        cargo build --release
sudo install \
    ./ssh-fetch-keys/target/x86_64-unknown-linux-musl/release/ssh-fetch-keys \
    /bin

sudo install \
    -D \
    --mode=644 \
    --target-directory=/etc/ssh/sshd_config.d \
    ./ssh-fetch-keys/conf/01-ssh-fetch-keys.conf

sudo install \
    -D \
    --mode=644 \
    --target-directory=/etc/ssh \
    ./ssh-fetch-keys/conf/fetch_keys.conf

TEMP_DIR_SELINUX_SSHD=$(mktemp --directory)
sudo checkmodule \
    --mls \
    -m \
    --output ${TEMP_DIR_SELINUX_SSHD}/ssh-fetch-keys.mod \
    ./ssh-fetch-keys/conf/ssh-fetch-keys.te
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
