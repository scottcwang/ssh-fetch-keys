# `ssh-fetch-keys`

An [`sshd_config` `AuthorizedKeysCommand`](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand) to fetch users' public keys from GitHub, et al. May also be used as an `sshd_config` `AuthorizedPrincipalsCommand` or an `ssh_config` `KnownHostsCommand`.

## How it works

Upload your OpenSSH public key to your [GitHub account](https://github.com/settings/keys).

Set up the OpenSSH server as follows:

```bash
$ sudo tee /etc/ssh/sshd_config.d/01-ssh-fetch-keys.conf <<EOF >/dev/null
# Global configuration: sshd configuration
AuthorizedKeysCommand /bin/ssh-fetch-keys %u %k
AuthorizedKeysCommandUser root
EOF

$ sudo chmod 644 /etc/ssh/sshd_config.d/01-ssh-fetch-keys.conf

$ sudo tee /etc/ssh/fetch_keys.conf <<EOF >/dev/null
# Global configuration: source definitions file
github https://github.com/{1}.keys
EOF

$ sudo chmod 644 /etc/ssh/fetch_keys.conf

$ cat > ~/.ssh/fetch_keys <<EOF
# User configuration: user definitions file
# Replace scottcwang with your GitHub username
github scottcwang
EOF

$ chmod 644 ~/.ssh/fetch_keys
```

Now, connect to the `ssh` server with the private key corresponding to the one you uploaded to GitHub.

To find the user's public keys, `sshd` runs the `AuthorizedKeysCommand`, `ssh-fetch-keys`. Because the user definitions file (`~/.ssh/fetch_keys`) specifies the `github` source with the `scottcwang` token, and the source definitions file (`/etc/ssh/fetch_keys.conf`) defines the `github` source as the `https://github.com/{1}.keys` URL template, `ssh-fetch-keys` fetches the public key hosted at `https://github.com/scottcwang.keys`, which `sshd` uses to authenticate the user. `ssh-fetch-keys` caches the downloaded public key for use if `github.com` is inaccessible in the future.

## Security

In the above example, the server trusts that `github.com` is not compromised, and that only the authorized user is able to change the keys hosted at `https://github.com/scottcwang.keys`.

## Installation

Requires OpenSSH 6.2 (2013-03-22).

```bash
git clone https://github.com/scottcwang/ssh-fetch-keys.git
sudo docker run \
    --rm \
    --interactive \
    --tty \
    --volume $(pwd)/ssh-fetch-keys:/usr/src/ssh-fetch-keys:Z \
    --workdir /usr/src/ssh-fetch-keys \
    docker.io/rust \
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

## Usage

To customise the behaviour of `ssh-fetch-keys`, adjust the options to the `AuthorizedKeysCommand` specified in `/etc/ssh/sshd_config.d/01-ssh-fetch-keys.conf`. `ssh-fetch-keys` offers the following arguments and options.

```
Usage: ssh-fetch-keys [OPTIONS] [USERNAME] [KEY]

Arguments:
  [USERNAME]  Username for which to fetch keys. If not specified, defaults to the user that owns this process. When specifying this program for the AuthorizedKeysCommand in sshd_config, use the token %u, which sshd will substitute with the username of the user who is requesting to authenticate
  [KEY]       Key to look for (will stop once found). Optional. When specifying this program for the AuthorizedKeysCommand in sshd_config, use the token %k, which sshd will substitute with the public key sent by the client

Options:
  -U, --override-user-def <OVERRIDE_USER_DEF>
          Override user definition string. Takes precedence over --user-defs
  -u, --user-defs <USER_DEFS>
          User definitions file path. Defaults to ~<username>/.ssh/fetch_keys
  -S, --override-source-def <OVERRIDE_SOURCE_DEF>
          Override source definition string. Takes precedence over --source-defs
  -s, --source-defs <SOURCE_DEFS>
          Source definitions file path. Defaults to /etc/ssh/fetch_keys.conf
  -c, --cache-directory <CACHE_DIRECTORY>
          Cache directory path. Defaults to ~<username>/.ssh/fetch_keys.d/
      --cache-stale <CACHE_STALE>
          Skip making a new request to a source if it has been less than this many seconds since that source's cache was last modified. 0 to ignore any caches [default: 60]
      --request-timeout <REQUEST_TIMEOUT>
          Timeout for requests in seconds [default: 5]
  -v, --verbose...
          More output per occurrence
  -q, --quiet...
          Less output per occurrence
  -h, --help
          Print help
  -V, --version
          Print version
```

### Source definitions format

Each line of the source definitions file (or override source definitions string) specifies the following fields, separated by spaces:

- (Optional) An options string to be prepended to every returned key, which `ssh-fetch-keys` will handle as described below
- Name of the source
- URL template, where token placeholders are specified using `{1}`, `{2}`, etc.
- Comment (ignored)

Empty lines and comment lines beginning `#` are ignored.

### User definitions format

Each line of the user definitions file (or override user definitions string) specifies the following fields, separated by spaces:

- (Optional) An options string to be prepended to every returned key, which `ssh-fetch-keys` will handle as described below
- Name of the source
- Token value to be substituted for placeholder `{1}`
- Token value to be substituted for placeholder `{2}`
- etc. Any unused tokens are ignored

Empty lines and comment lines beginning `#` are ignored.

`ssh-fetch-keys` processes each of the user definitions lines in order and prints the fetched public keys to standard output, from which `sshd` reads them. If `ssh-fetch-keys` is executed with a `KEY` argument, it stops when one of the fetched public keys contains the `KEY` argument.

### Options string

The source definition line and the user definition line may specify an options string to be prepended to each output key line. This is useful for specifying [`sshd` `AUTHORIZED_KEYS` options](https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT), or [`ssh` `SSH_KNOWN_HOSTS`](https://man.openbsd.org/sshd.8#SSH_KNOWN_HOSTS_FILE_FORMAT) remote hostnames or addresses.

Option strings may be specified in more than one of the fetched user key, the source definition line, and the user definition line. If this is the case, the options strings are concatenated together, separated by commas, in this order: those of the fetched public key, followed by those of the user definition line, followed by those of the source definition line. This means that the source definition line's options will take precedence over the user definition line's options, which will take precedence over the fetched public key's options.

Since `sshd` prohibits the `command="command"`, `principals="principals"`, and `from="pattern-list"` options from appearing more than once in a given `AUTHORIZED_KEYS` line, `ssh-fetch-keys` handles these options specially. Therefore, if any of these options is specified in more than one of the fetched user key, the source definition line, and the user definition line, then `ssh-fetch-keys` will only preserve the option value specified in the source definition line if it exists, and otherwise it will only preserve the option value specified in the user definition line.

Similarly, amongst `ssh` `SSH_KNOWN_HOSTS` host key tags, `@revoked` will take precedence over `@cert-authority`.

### Example

Let's say the user definitions file at `~user/.ssh/fetch_keys` is as follows:

```
pty,command="user.sh" sourceA token1 token2
sourceB token1 token2
```

and the source definitions file at `/etc/ssh/sshd_config.d/01-ssh-fetch-keys.conf` is as follows:

```
restrict,command="source.sh" sourceA https://a.example.com/{1}-{2}
sourceB https://b.example.com/{1} comment
```

and the URL contents for `https://a.example.com/token1-token2` are as follows:

```
X11-forwarding ssh-ed25519 AAAA123...
agent-forwarding,command="fetch.sh" ssh-rsa AAAA234...
```

and the URL contents for `https://b.example.com/token1` are as follows:

```
ssh-ed25519 AAAA345...
ssh-rsa AAAA456...
```

The command `ssh-fetch-keys user AAAA345...` will print the following to standard output:

```
X11-forwarding,pty,restrict,command="source.sh" ssh-ed25519 AAAA123...
agent-forwarding,pty,restrict,command="source.sh" ssh-rsa AAAA234...
ssh-ed25519 AAAA345...
```

Note that `sshd` invokes `AuthorizedUsersCommand` more than once during authentication; hence, `ssh-fetch-keys` caches the fetched public keys to avoid repeated requests to the same URL. This behaviour can be customised by way of the `--cache-stale` option.

### Suggestions for using a mirror server as a `ssh-fetch-keys` source

In general, `ssh-fetch-keys` uses a user definitions file to look up a URL template, interpolates the URL template with user details, and downloads and caches the content at the URL.

Consider a scenario where many users need to be able to connect to many remote destinations with the same username. It would be infeasible to maintain in every remote destination an updated set of all the users' public keys in `~/.ssh/authorized_keys`. Even if each remote destination were to be individually configured with `ssh-fetch-keys`, every user would still need to maintain their user definitions in every remote destination's `~/.ssh/fetch_keys`.

Instead, users can maintain their user definitions on a single mirror server. Such a server would listen on a `https://mirror.example.com/keys?username=<username>` endpoint for HTTP requests from remote destinations, and respond with the known public keys for the username in the URL query string.

One way to do so is for the mirror server to use [`shell2http`](https://github.com/msoap/shell2http), or similar, to execute `ssh-fetch-keys`, obtaining the user's public keys by parsing `~username/.ssh/fetch_keys` on the mirror server:

```bash
sudo shell2http -form /keys 'ssh-fetch-keys $v_username'
```

Each remote destination's `sshd_config` would then have an identical `AuthorizedKeysCommand` configuration, such as the following, that specifies the mirror server and the username query parameter in the source definition URL:

```
AuthorizedKeysCommand /bin/ssh-fetch-keys --override-source-def 'mirror http://mirror.example.com/keys?username=%u' --override-user-def "mirror" --cache-directory /dev/null %u %k
AuthorizedKeysCommandUser root
```

When a user authenticates to the remote destination, the remote destination's `sshd` executes `ssh-fetch-keys` with an overridden user definition. Thus, `ssh-fetch-keys` omits looking for the user's `~username/.ssh/fetch_keys` on the remote destination; rather, it queries the mirror server by making a request to `https://mirror.example.com/keys?username=<username>`. When the mirror server responds with the user's public keys, `ssh-fetch-keys` provides them to the remote destination's `sshd`.

In this way, users need only maintain their user definitions in a single location, viz. `~username/.ssh/fetch_keys` on the mirror server; `ssh-fetch-keys` relays their public keys from the mirror server to any remote destination the user authenticates to.

Alternatively, the mirror server can be constructed to obtain the users' public keys from their `~username/.ssh/authorized_keys`, a database, or a directory service.

### Suggestions for using a certificate authority in conjunction with `ssh-fetch-keys` as an `AuthorizedPrincipalsCommand`

Similarly, `ssh-fetch-keys` may also be invoked by an [`sshd_config` `AuthorizedPrincipalsCommand`](https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand), which is supported beginning with OpenSSH 6.9 (2015-07-01). This requires that a certificate authority's public key be listed in [`sshd_config` `TrustedUserCAKeys`](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

This is useful to locally pin a certificate authority key, while allowing for a regularly changing list of accepted certificate principal names. For instance, to implement single-use certificates, a certificate authority daemon can serve an HTTP URL such as `https://ca.example.com/principals?fingerprint=<fingerprint>`, which URL responds, if and only if the fingerprint has not yet been queried, with the name of the principal corresponding to the certificate with the given fingerprint. `sshd_config` would be configured with an `AuthorizedPrincipalsCommand` resembling the following:

```
AuthorizedPrincipalsCommand /bin/ssh-fetch-keys --override-source-def "ca http://ca.example.com/principals?fingerprint=%f" --override-user-def "ca"
AuthorizedPrincipalsCommandUser root
```

where `%f` is the [`sshd_config` `AuthorizedPrincipalsCommand` token](https://man.openbsd.org/sshd_config#TOKENS) representing the certificate fingerprint. When the user presents a certificate, `ssh-fetch-keys` requests `https://ca.example.com/principals?fingerprint=<fingerprint>`, whereupon the certificate authority daemon responds with the principal name of the corresponding certificate and records the fingerprint as having been queried.

If the certificate authority's public key itself changes frequently, it is tiresome to repeatedly update the `TrustedUserCAKeys` parameter. Instead, use `ssh-fetch-keys` as the `AuthorizedUsersCommand` parameter, but have the certificate authority daemon respond with the certificate authority key, specifying the `cert-authority` and `principals` key options.

### Suggestions for using `ssh-fetch-keys` as an `ssh_config KnownHostsCommand`

`ssh-fetch-keys` may be used on the `ssh` client as an [`ssh_config` `KnownHostsCommand`](https://man.openbsd.org/ssh_config#KnownHostsCommand), which is supported beginning with OpenSSH 8.5 (2021-03-03). This replaces the `known_hosts` file of cached host keys, obviating the need to trust host keys on first use (TOFU) and update the key in `known_hosts` when it changes on the host.

For example, if the remote hosts at the domain `ssh.example.com` are all trusted, they can serve their own host keys at `https://<remote host>.ssh.example.com/host-keys`, such as by using [`shell2http`](https://github.com/msoap/shell2http):

```bash
sudo shell2http -form /host-keys 'cat /etc/ssh/ssh_host_*_key.pub'
```

Clients can then use the following `ssh-config` to obtain the most recent host key on each login:

```
Host *.ssh.example.com
    KnownHostsCommand /bin/ssh-fetch-keys --override-source-def "%H hostkeys http://%H/host-keys" --override-user-def "hostkeys"
```

where `%H` is the [`ssh_config` `KnownHostsCommand` token](https://man.openbsd.org/ssh_config#TOKENS) representing the remote hostname or address.

Alternatively, the administrator can set up a mirror server for host keys, and clients can query it to find out the host keys for any desired host in the domain. In this way, the client needs to trust only the mirror server, as opposed to each individual host in the domain.

## Changelog

- `0.3.0`:
  - Support prepended key options strings (used for `sshd` `AUTHORIZED_KEYS` options and `ssh` `SSH_KNOWN_HOSTS` remote hostnames or addresses)
  - Use `reqwest`; drop dependency on `curl`
- `0.2.0`: add `--override-user-def`, `--override-source-def` options
- `0.1.0`: initial release

## Disclaimer

This software hasn't been reviewed for security: please understand that you use it at your own risk.
