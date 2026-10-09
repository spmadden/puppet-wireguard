class { 'wireguard::roadwarrior':
  interface   => 'wg0',
  addresses   => ['10.100.0.1/24', 'fd42:100:100::1/64'],
  listen_port => 51820,
  mtu         => 1380,
  peers       => {
    'laptop' => {
      'public_key'         => 'REPLACE_WITH_VALID_LAPTOP_PUBLIC_KEY',
      'allowed_ips'        => ['10.100.0.10/32', 'fd42:100:100::10/128'],
      'preshared_key_file' => '/etc/wireguard/psks/wg0-laptop.psk',
    },
    'phone' => {
      'public_key'  => 'REPLACE_WITH_VALID_PHONE_PUBLIC_KEY',
      'allowed_ips' => ['10.100.0.11/32', 'fd42:100:100::11/128'],
    },
  },
}
