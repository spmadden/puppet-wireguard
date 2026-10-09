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

---

## Windows road-warrior clients (`wireguard::windows::tunnel`)

This version extends the Linux WireGuard module with a **Windows client** implementation.
It is independent of Hiera. The signed WireGuard for Windows application must already be
installed (e.g. via an MSI deployed separately). The Puppet agent must run as **LocalSystem**.

### Files

- `manifests/windows.pp`: shared WireGuardManager service and helper installation.
- `manifests/windows/tunnel.pp`: one tunnel resource, `always_on` or `user_controlled`.
- `templates/windows/client.conf.epp`: publicly readable-by-Puppet fields only;
  never contains `PrivateKey` or `PresharedKey`.
- `files/windows-manage.ps1`: secure Windows provisioning, DPAPI, service lifecycle.
- `examples/windows_site.pp`: direct Puppet example (no Hiera).

### Operating modes

| Setting | Always-on | User-controlled |
|---|---|---|
| Puppet ensures service running | Yes | No |
| Puppet preserves the user disconnect | No | Yes |
| Profile remains visible in the GUI when disconnected | Yes | Yes |
| Profile changes while connected | Service refreshed | Service refreshed |
| Profile changes while disconnected | Tunnel started | Remains disconnected |

**Important Windows nuance:** The WireGuard GUI deletes a tunnel service on disconnect
and recreates it on reconnect. Thus `user_controlled` explicitly does *not* ensure
service presence. WireGuard creates a service with an Automatic start type whenever
a user connects; a connection left active may therefore reconnect at boot. The mode
means Puppet does not override a user disconnect, not that Windows guarantees a
freshly disconnected state on every reboot. If strict no-connect-on-boot policy is
required, add a separately tested startup policy. Do **not** unconditionally use
`service { 'WireGuardTunnel$wg0': ensure => stopped }`.

### Node-local identity

At first Puppet apply the helper generates an independent client private key with
`wg genkey`, stores it in a protected local DPAPI blob, derives the public key, and
writes:

```
C:\ProgramData\WireGuardPuppet\Secrets\wg0.private.dpapi
C:\ProgramData\WireGuardPuppet\PublicKeys\wg0.pub
```

The actual WireGuard tunnel configuration is encrypted in WireGuard's native store:

```
C:\Program Files\WireGuard\Data\Configurations\wg0.conf.dpapi
```

This helper uses `CryptProtectData` with the tunnel name as the DPAPI description,
matching the official WireGuard Windows format. It does not use the less secure
machine-wide DPAPI flag. Keys are protected for LocalSystem and are not in Puppet.
If a private key blob is missing while an encrypted config exists, the helper
refuses to silently create a new identity.

### PSK enrollment (one time per tunnel)

1. On the Linux server, locate the PSK created by the server-side module, e.g.
   `/etc/wireguard/psks/wg0-laptop.psk`.
2. Using a **separate secure authenticated channel**, transfer that *same* key
   onto the Windows node. Do **not** store its contents in Puppet source, Hiera,
   reports, or an `exec` command line.
3. Run Puppet once to create `C:\ProgramData\WireGuardPuppet\Secrets\` and its
   restricted ACL; a first run with `preshared_key => true` will report that it
   needs the PSK until it is enrolled.
4. Put the PSK as `C:\ProgramData\WireGuardPuppet\Secrets\wg0.psk.import`
   using an elevated, secure provisioning process. It must contain WireGuard's
   standard 32-byte base64 key.
5. Run Puppet again as LocalSystem. The helper encrypts the PSK into
   `wg0.psk.dpapi` and deletes the transient plaintext input. It then embeds
   the PSK into the DPAPI-encrypted WireGuard tunnel configuration in memory.
6. After reading `...\PublicKeys\wg0.pub`, add that public key to the server's
   Puppet peer declaration, using the client's assigned IPv4/IPv6 `/32`/`/128`.

Carefully protect `.psk.import` while present. Deleting a plaintext file does not
promise forensic erasure from SSD snapshots/backups. Use secure transfer and avoid
transfers that leave an extra copy in a normal user's Downloads directory.
The client and server PSKs must be the SAME bytes; never independently generate
one on both sides.

### User control

Run the WireGuard manager normally for an admin UI. For suitably provisioned
non-admin users, WireGuard supports `HKLM\SOFTWARE\WireGuard\LimitedOperatorUI`
set to `DWORD(1)` plus membership in the Windows Network Configuration Operators
group. This UI can start and stop tunnels but cannot edit or export them.

For example, from an elevated administrator PowerShell:

```powershell
New-Item -Path 'HKLM:\SOFTWARE\WireGuard' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\WireGuard' -Name LimitedOperatorUI -PropertyType DWord -Value 1 -Force
```

Group membership must be separately granted and refreshed at sign-in.

### Operational diagnostics

```powershell
Get-Service -Name 'WireGuardManager'
Get-Service -Name 'WireGuardTunnel$wg0' -ErrorAction SilentlyContinue
& 'C:\Program Files\WireGuard\wg.exe' show wg0
& 'C:\Program Files\WireGuard\wireguard.exe' /dumplog
```

`wg show` will report an error while a user-controlled tunnel is disconnected;
that is normal. On `ensure => absent`, Puppet removes the encrypted tunnel
configuration and any running service, but deliberately retains client key
material for recovery/re-enrollment.

### Safety and testing limitations

- The Windows helper is designed for Windows PowerShell 5.1 and LocalSystem.
- Normal public configuration changes may briefly interrupt an active tunnel
  because WireGuard's Windows service is recreated to load the updated profile.
- The helper attempts to restore the prior encrypted profile on update failure;
  it still exits unsuccessfully so Puppet surfaces the problem.
- Tunnel `AllowedIPs`, firewall, split DNS, and server peer enrollment must be
  coordinated separately; Windows does not support Linux `PostUp` key loading
  without a dangerous system registry setting, which is not used here.
- This environment did not provide a Windows VM, PowerShell, Puppet agent, or
  WireGuard driver. **Source-level checks only** were possible. Test on a Windows
  VM/lab laptop before deployment, especially first-run encryption, GUI reconnect,
  updates to an active tunnel, DPAPI decrypt, and rollback.
