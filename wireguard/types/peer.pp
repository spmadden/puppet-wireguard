# Peer public data and an optional *path* to a locally generated PSK.
type Wireguard::Peer = Struct[{
  'public_key'                      => String[1],
  'allowed_ips'                     => Array[String[1], 1],
  Optional['endpoint']              => String[1],
  Optional['persistent_keepalive']  => Integer[0, 65535],
  Optional['preshared_key_file']    => Pattern[/\A\/etc\/wireguard\/psks\/[a-zA-Z0-9_.-]+\.psk\z/],
}]
