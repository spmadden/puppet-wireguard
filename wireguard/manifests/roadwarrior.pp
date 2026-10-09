# Manage one server-side WireGuard interface with multiple roaming peers.
# Server identity is generated and retained exclusively on this node.
class wireguard::roadwarrior (
  Pattern[/\A[a-zA-Z0-9_=+.-]{1,15}\z/] $interface = 'wg0',
  Array[String[1], 1] $addresses = ['10.100.0.1/24'],
  Integer[1, 65535] $listen_port = 51820,
  Optional[Integer[576, 9000]] $mtu = undef,
  Hash[Pattern[/\A[a-zA-Z0-9_.-]+\z/], Wireguard::Peer] $peers = {},
  String[1] $package_name = 'wireguard-tools',
) {
  $config_file      = "/etc/wireguard/${interface}.conf"
  $private_key_file = "/etc/wireguard/${interface}.key"
  $public_key_file  = "/etc/wireguard/${interface}.pub"
  $staging_dir      = '/var/lib/puppet-wireguard'
  $staged_file      = "${staging_dir}/${interface}.conf"
  $helper_file      = '/usr/local/libexec/wireguard-helper'
  $service_name     = "wg-quick@${interface}"

  package { $package_name:
    ensure => installed,
  }

  file { '/etc/wireguard':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    require => Package[$package_name],
  }

  file { $staging_dir:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/usr/local/libexec':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { $helper_file:
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    source  => 'puppet:///modules/wireguard/wireguard-helper',
    require => File['/usr/local/libexec'],
  }

  # Do not declare the key file before key generation: ensure => file
  # would create an empty file and defeat the creates guard.
  exec { "wireguard-generate-key-${interface}":
    command   => [$helper_file, 'generate-key', $private_key_file],
    creates   => $private_key_file,
    logoutput => false,
    require   => [File[$helper_file], File['/etc/wireguard']],
  }

  file { $private_key_file:
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    require => Exec["wireguard-generate-key-${interface}"],
  }

  exec { "wireguard-update-public-key-${interface}":
    command => [
      $helper_file, 'update-public-key',
      $private_key_file, $public_key_file,
    ],
    unless => [[
      $helper_file, 'public-key-matches',
      $private_key_file, $public_key_file,
    ]],
    logoutput => false,
    require   => File[$private_key_file],
  }

  file { $public_key_file:
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Exec["wireguard-update-public-key-${interface}"],
  }

  # A valid basename lets 'wg-quick strip' process this staged file.
  file { $staged_file:
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => epp('wireguard/roadwarrior.conf.epp', {
      'addresses'        => $addresses,
      'listen_port'      => $listen_port,
      'mtu'              => $mtu,
      'private_key_file' => $private_key_file,
      'peers'            => $peers,
    }),
    require => File[$staging_dir],
  }

  # Only if staged contents differ: validate, then atomically replace live.
  # A validation failure leaves the previous live configuration untouched.
  exec { "wireguard-install-config-${interface}":
    command => [
      $helper_file, 'install-config',
      $staged_file, $config_file,
    ],
    unless => [[
      '/usr/bin/cmp', '-s',
      $staged_file, $config_file,
    ]],
    require => [
      File[$staged_file],
      File[$helper_file],
      File[$private_key_file],
      File['/etc/wireguard'],
    ],
    notify => Exec["wireguard-syncconf-${interface}"],
  }

  # First run: installed config + key, then service starts. Peer updates
  # are applied by syncconf rather than restarting this service.
  service { $service_name:
    ensure  => running,
    enable  => true,
    require => Exec["wireguard-install-config-${interface}"],
  }

  # wg-quick's Address is not managed by wg syncconf. If the running IPv4
  # address changes, the interface must be restarted. This is disruptive.
  $address_check_command = [
    $helper_file,
    'addresses-match',
    $interface,
  ] + $addresses

  exec { "wireguard-correct-address-${interface}":
    command => [
      '/usr/bin/systemctl',
      'restart',
      $service_name,
    ],

    unless => [$address_check_command],

    require => Service[$service_name],
  }
  
  #
  # Reconcile interface MTU without restarting WireGuard.
  #
  # MTU is a wg-quick directive, not a wg syncconf directive.
  # Apply it directly to the live Linux network interface.
  #
  if $mtu != undef {
    exec { "wireguard-correct-mtu-${interface}":
      command => [
        '/usr/sbin/ip', 'link', 'set', 'dev',
        $interface, 'mtu', "${mtu}",
      ],

      unless => "/usr/bin/grep -qx ${mtu} /sys/class/net/${interface}/mtu",

      require => Exec["wireguard-correct-address-${interface}"],
      before  => Exec["wireguard-syncconf-${interface}"],
    }
  }

  # WireGuard-native changes (peers, port) are synced without a restart.
  # A failed strip cannot be passed to syncconf as an empty config.
  exec { "wireguard-syncconf-${interface}":
    command     => [$helper_file, 'sync-config', $interface, $config_file],
    refreshonly => true,
    require     => Exec["wireguard-correct-address-${interface}"],
  }

  # Repair a live private-key mismatch (e.g. deliberate node-local rotation).
  exec { "wireguard-apply-private-key-${interface}":
    command => [
      '/usr/bin/wg', 'set',
      $interface, 'private-key', $private_key_file,
    ],
    unless => [[
      $helper_file, 'key-matches',
      $interface, $private_key_file,
    ]],
    logoutput => false,
    require   => [
      Exec["wireguard-syncconf-${interface}"],
      File[$public_key_file],
    ],
  }
}
