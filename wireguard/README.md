# wireguard::roadwarrior

A Puppet module for one server-side Linux/systemd WireGuard interface with multiple roaming peers. No Hiera is used.

* Server private key is generated **locally**, never stored in the Puppet catalog.
* Candidate configuration is staged at `/var/lib/puppet-wireguard/<iface>.conf`.
* A changed candidate is checked with `wg-quick strip` and atomically copied into `/etc/wireguard/<iface>.conf`.
* `wg syncconf` applies peer/listen-port changes without a service restart.
* A change to the interface IPv4 address triggers an interface restart.
* Client keys/client configs, host forwarding, NAT, firewall and routed subnet route reconciliation are **out of scope**.

## Installation

Put this folder in the environment's modulepath under the exact name `wireguard`, e.g. `/etc/puppetlabs/code/environments/production/modules/wireguard/`.

Change the example metadata fields to your organization.

## Example site.pp

```puppet
class { 'wireguard::roadwarrior':
  interface   => 'wg0',
  address     => '10.100.0.1/24',
  listen_port => 51820,
  peers       => {
    'laptop' => {
      'public_key'  => 'REPLACE_WITH_CLIENT_PUBLIC_KEY',
      'allowed_ips' => ['10.100.0.10/32'],
    },
    'phone' => {
      'public_key'  => 'REPLACE_WITH_CLIENT_PUBLIC_KEY',
      'allowed_ips' => ['10.100.0.11/32'],
    },
  },
}
```

## Checking

```bash
puppet parser validate manifests/roadwarrior.pp types/peer.pp
puppet epp validate templates/roadwarrior.conf.epp
bash -n files/wireguard-helper
sudo puppet agent -t
sudo cat /etc/wireguard/wg0.pub
sudo wg show wg0
```

## Security

`/etc/wireguard/wg0.key` is `root:root 0600`; protect it with encrypted host backups. Deleting it rotates the server identity and forces changes on every client. `/etc/wireguard/wg0.conf` is `0600` and contains no server private key. A private-key mismatch on a running interface is corrected using `wg set ... private-key /etc/wireguard/wg0.key`.

## Limitations

`wg-quick strip` is only a partial syntax check. It does not fully validate `wg` configuration, CIDRs, or operating-system route conflicts. A config that passes this check can still fail during service startup or `wg syncconf`.

On a live interface, `syncconf` does not create/remove the automatic OS routes `wg-quick` normally creates on `up`. The class is designed for road-warrior `/32` addresses within the interface's connected subnet; manage additional routes separately or restart the interface when changes to routed subnets are needed.

This module assumes Linux, systemd, `wg-quick`, and paths common on Debian/Ubuntu/RHEL-family distributions. Verify executable locations on your OS.
