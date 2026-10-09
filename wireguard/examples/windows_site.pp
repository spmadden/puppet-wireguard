# Install WireGuard for Windows separately (signed upstream MSI or managed package).
# Tunnel PSKs need one-time secure enrollment from the server.

wireguard::windows::tunnel { 'wg0':
  mode                 => 'user_controlled',
  addresses            => ['10.100.0.10/32', 'fd42:100:100::10/128'],
  server_public_key    => 'REPLACE_WITH_SERVER_PUBLIC_KEY',
  endpoint             => 'vpn.example.com:51820',
  allowed_ips          => ['10.100.0.0/24', 'fd42:100:100::/64'],
  dns                  => ['10.100.0.1'],
  mtu                  => 1380,
  persistent_keepalive => 25,
  preshared_key        => true,
}

wireguard::windows::tunnel { 'wg1':
  mode                 => 'always_on',
  addresses            => ['10.101.0.10/32'],
  server_public_key    => 'REPLACE_WITH_SECOND_SERVER_PUBLIC_KEY',
  endpoint             => 'vpn2.example.com:51820',
  allowed_ips          => ['10.101.0.0/24'],
  mtu                  => 1380,
}
