# Replace the example public keys with the actual peers' public keys.
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
