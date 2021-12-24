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

### Basic usage

Upload your public key to your [GitHub account](https://github.com/settings/keys). Then do the following, replacing `username` with your GitHub username:

```bash
echo "github username" > ~/.ssh/fetch_keys
chmod 644 ~/.ssh/fetch_keys
```

Now authenticate to `ssh` with the corresponding private key.
`sshd` will call `ssh-fetch-keys`, which will retrieve your public keys from `https://github.com/username.keys` and cache them in `~/.ssh/fetch_keys.d/`, for use if GitHub is inaccessible.

### Options

To customise the behaviour of `ssh-fetch-keys`, specify options to the `AuthorizedKeysCommand` specified in `/etc/ssh/sshd_config.d/01-ssh-fetch-keys.conf`. `ssh-fetch-keys` uses the following syntax:

```
USAGE:
    ssh-fetch-keys [FLAGS] [OPTIONS] [ARGS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Verbosity. Can be given multiple times

OPTIONS:
    -U, --override-user-def <override-user-def>
            Override user definition string. Takes precedence over --user-defs

    -u, --user-defs <user-defs>
            User definitions file path. Defaults to ~<username>/.ssh/fetch_keys

    -S, --override-source-def <override-source-def>
            Override source definition string. Takes precedence over --source-defs

    -s, --source-defs <source-defs>
            Source definitions file path. Defaults to /etc/ssh/fetch_keys.conf

    -c, --cache-directory <cache-directory>            Cache directory path. Defaults to ~<username>/.ssh/fetch_keys.d/
        --cache-stale <cache-stale>
            Skip making a new request to a source if it has been less than this many seconds since that source's cache
            was last modified. 0 to ignore any caches. Default 60
        --request-timeout <request-timeout>            Timeout for requests in seconds. Default 5

ARGS:
    <username>    Username for which to fetch keys. If not specified, defaults to the user that owns this process.
                  When specifying this program for the AuthorizedKeysCommand in sshd_config, use the token %u, which
                  sshd will substitute with the username of the user who is requesting to authenticate
    <key>         Key to look for (will stop once found). Optional. When specifying this program for the
                  AuthorizedKeysCommand in sshd_config, use the token %k, which sshd will substitute with the public
                  key sent by the client
```

### Applications

In general, `ssh-fetch-keys` obtains public keys by parsing user definitions and making HTTP requests accordingly. One possibility is to use `ssh-fetch-keys` to maintain the user definitions at a centralised source.

For example, consider a scenario where many clients need to be able to connect to many remote destinations with the same username. It would be infeasible to maintain in every remote destination an updated set of all the clients' public keys in `~/.ssh/authorized_keys`. Even if each remote destination were individually configured with `ssh-fetch-keys`, every client would still need to maintain their user definitions in every remote destination's `~/.ssh/fetch_keys`. Although `openssh` supports certificate keys, they suffer from the concomitant maintenance burdens of certificate issuance, distribution, revocation, and rotation.

Instead, clients can maintain their user definitions on a single mirror server. Such a server would listen on a `/keys?username=` endpoint for HTTP requests from remote destinations, and respond with the known public keys for the username in the URL query string. To do so, the mirror server can use [`shell2http`](https://github.com/msoap/shell2http), or similar, to execute `ssh-fetch-keys`, obtaining the client's public keys by parsing `~username/.ssh/fetch_keys` on the mirror server:

```bash
sudo shell2http -form /keys 'ssh-fetch-keys $v_username'
```

Each remote destination would then have an identical configuration for `ssh-fetch-keys` that specifies the mirror server and the username query parameter in a URL:

```bash
# /etc/ssh/sshd_config.d/01-ssh-fetch-keys.conf
AuthorizedKeysCommand /bin/ssh-fetch-keys --override-source-def 'mirror http://mirror-host/keys?username={1}' --override-user-def "mirror %u" --cache-directory /dev/null %u %k
AuthorizedKeysCommandUser root
```

When a client authenticates to the remote destination, the remote destination's `sshd` executes `ssh-fetch-keys` with an overridden user definition, so omits looking for the client's `~username/.ssh/fetch_keys` on the remote destination. Rather, it queries the mirror server by making a request to `http://mirror-host/keys?username=username`; the mirror server responds to the remote destination's `sshd` with the client's public keys.

In this way, clients need only maintain their user definitions in a single location, viz. `~username/.ssh/fetch_keys` on the mirror server; their public keys are relayed to any remote destination the client authenticates to.

Alternatively, the mirror server can be constructed to obtain the client's public keys from their `~username/ssh/authorized_keys`, a database, or a directory service.

## Disclaimer

This software hasn't been reviewed for security: please understand that you use it at your own risk.
