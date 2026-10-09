# Road-warrior peer on a server interface. Endpoint is normally omitted.
type Wireguard::Peer = Struct[{
  'public_key'                      => String[1],
  'allowed_ips'                     => Array[String[1], 1],
  Optional['endpoint']              => String[1],
  Optional['persistent_keepalive']  => Integer[0, 65535],
}]
