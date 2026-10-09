# Puppet wireguard::roadwarrior

Puppet class for a Linux `wg-quick@<interface>` WireGuard road-warrior server.
No Hiera required. Peer definitions are passed in the class declaration.

## Security model

- The server private key is generated once, on the managed node, under `/etc/wireguard/<iface>.key` (0600).
- For any peer with `preshared_key_file`, `wg genpsk` generates a distinct PSK **on the managed node** if the specified file does not already exist. The PSK remains in `/etc/wireguard/psks/` (directory 0700, file 0600).
- No private key or PSK value is in Puppet source, the compiled catalog, the EPP-rendered config, or the persistent `wg0.conf` file.
- The Puppet-managed `wg0.conf` contains a `# PuppetPSKFile = /etc/wireguard/psks/...` comment for PSK-enabled peers.
- On systemd startup, `wg-quick`'s `PostUp` hook loads the private key and then loads each peer PSK directly from its file using `wg set`.
- On Puppet changes, the helper creates a **short-lived 0600 temp config under `/etc/wireguard`** containing PSKs, calls `wg syncconf`, and deletes the temp file. Thus `syncconf` cannot accidentally clear PSKs omitted from the public desired config.
- Every Puppet run checks live PSKs for drift (e.g. after out-of-band rotation) and resynchronizes if needed.
- `wg showconf`, `wg show <iface> preshared-keys` and root/kernel access can expose secrets. Filesystem security and root access still matter.

## Example

```puppet
class { 'wireguard::roadwarrior':
  interface   => 'wg0',
  addresses   => ['10.100.0.1/24', 'fd42:100:100::1/64'],
  listen_port => 51820,
  mtu         => 1380,
  peers       => {
    'laptop' => {
      'public_key'         => 'REPLACE_WITH_LAPTOP_PUBLIC_KEY',
      'allowed_ips'        => ['10.100.0.10/32', 'fd42:100:100::10/128'],
      'preshared_key_file' => '/etc/wireguard/psks/wg0-laptop.psk',
    },
    'phone' => {
      'public_key'  => 'REPLACE_WITH_PHONE_PUBLIC_KEY',
      'allowed_ips' => ['10.100.0.11/32'],
    },
  },
}
```

For each PSK-enabled peer, transfer the PSK **securely** to the client and add the same key to the client's `[Peer]` (server) section:

```ini
[Peer]
PublicKey = SERVER_PUBLIC_KEY
PresharedKey = SAME_KEY_FROM_SERVER_PSK_FILE
Endpoint = vpn.example.net:51820
AllowedIPs = 10.100.0.0/24, fd42:100:100::/64
```

Do not post PSKs in tickets, logs, Puppet parameters, plaintext Git, or chat. Existing clients will **stop handshaking** when a server PSK is enabled until they have the matching PSK.

## Working files

```
/etc/wireguard/wg0.conf            # Puppet-managed, no key material
/etc/wireguard/wg0.key             # Private server key, root-only
/etc/wireguard/wg0.pub             # Public server key
/etc/wireguard/psks/wg0-laptop.psk # Per-peer PSK, root-only
/var/lib/puppet-wireguard/wg0.conf # Staged Puppet-managed config, no secrets
```

Existing PSKs and keys are never overwritten automatically. Removing a peer from Puppet removes it from WireGuard's *active configuration* but intentionally does **not** delete its archived PSK file (to avoid accidental secret loss). Back up server and PSK keys using an encrypted backup mechanism. Before intentionally rotating, install the new key on both sides as a coordinated change.

## Limitations

- Assumes Linux, systemd, `iproute2`, bash, coreutils, `wg`, `wg-quick`, and a working kernel WireGuard device. The Puppet module installs `wireguard-tools`; other dependencies are normally provided by the OS.
- `wg-quick strip` checks basic parsing and filename conventions, **not complete WireGuard semantics**. An invalid public key or allowed IP can still make startup/sync fail.
- `wg syncconf` manages WireGuard-native settings. Interface addresses require a restart in this module; MTU is reconciled live. Route management beyond `wg-quick`'s startup behavior, IP forwarding, NAT, and firewall are outside its scope.
- Only peer PSK file paths under `/etc/wireguard/psks/*.psk` are accepted. Use a unique file for each peer.
- If a PSK file is missing it will be regenerated, yielding a new key requiring the client's matching key to be updated. Treat this as a backup/rotation event.
- A changed PSK key value is not validated by Puppet's type system; node helper checks base64 length/format before using it. Invalid PSKs fail closed rather than clearing the active configuration.

## Verification

```bash
puppet parser validate manifests/roadwarrior.pp types/peer.pp
puppet epp validate templates/roadwarrior.conf.epp
bash -n files/wireguard-helper
sudo puppet agent -t
sudo wg show wg0
sudo stat -c '%a %n' /etc/wireguard/wg0.key /etc/wireguard/psks/*.psk
```

Avoid invoking `wg show wg0 preshared-keys` on a terminal captured by session logging: it prints the actual PSK values.
