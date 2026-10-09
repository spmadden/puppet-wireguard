# Server-side WireGuard peers. Secrets generated exclusively on this node.
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
  $psk_dir          = '/etc/wireguard/psks'
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

  file { $psk_dir:
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    require => File['/etc/wireguard'],
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

  # Generate the server identity locally, only if absent.
  # Do not create a File resource before the generation exec.
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
    command   => [$helper_file, 'update-public-key', $private_key_file, $public_key_file],
    unless    => [[$helper_file, 'public-key-matches', $private_key_file, $public_key_file]],
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

  # Per-peer PSKs are generated on the node, never in Puppet data.
  # Paths are intentionally restricted to a root-only directory.
  $peers.each |String $peer_name, Wireguard::Peer $peer| {
    if $peer['preshared_key_file'] != undef {
      $psk_file = $peer['preshared_key_file']
      exec { "wireguard-generate-psk-${interface}-${peer_name}":
        command   => [$helper_file, 'generate-psk', $psk_file],
        creates   => $psk_file,
        logoutput => false,
        require   => [File[$helper_file], File[$psk_dir]],
        notify    => Exec["wireguard-syncconf-${interface}"],
      }

      file { $psk_file:
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
        require => Exec["wireguard-generate-psk-${interface}-${peer_name}"],
        before  => Exec["wireguard-install-config-${interface}"],
      }
    }
  }

  # No private key or PSK values appear in this staged or installed file.
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
      'config_file'      => $config_file,
      'helper_file'      => $helper_file,
      'peers'            => $peers,
    }),
    require => File[$staging_dir],
  }

  # Validate staged config and referenced PSKs; replace live config atomically.
  exec { "wireguard-install-config-${interface}":
    command => [$helper_file, 'install-config', $staged_file, $config_file],
    unless  => [['/usr/bin/cmp', '-s', $staged_file, $config_file]],
    require => [File[$staged_file], File[$helper_file], File[$private_key_file], File['/etc/wireguard']],
    notify  => Exec["wireguard-syncconf-${interface}"],
  }

  service { $service_name:
    ensure  => running,
    enable  => true,
    require => Exec["wireguard-install-config-${interface}"],
  }

  # wg syncconf cannot reconcile wg-quick Address directives.
  exec { "wireguard-correct-address-${interface}":
    command => ['/usr/bin/systemctl', 'restart', $service_name],
    unless  => [[$helper_file, 'addresses-match', $interface] + $addresses],
    require => Service[$service_name],
  }

  # wg-quick's MTU setting is also outside wg syncconf.
  if $mtu != undef {
    exec { "wireguard-correct-mtu-${interface}":
      command => ['/usr/sbin/ip', 'link', 'set', 'dev', $interface, 'mtu', "${mtu}"],
      unless  => "/usr/bin/grep -qx ${mtu} /sys/class/net/${interface}/mtu",
      require => Exec["wireguard-correct-address-${interface}"],
      before  => Exec["wireguard-syncconf-${interface}"],
    }
  }

  # Expand PSK paths to values in a short-lived root-only temp file,
  # then sync peers without restarting established sessions.
  exec { "wireguard-syncconf-${interface}":
    command     => [$helper_file, 'sync-config', $interface, $config_file],
    refreshonly => true,
    logoutput   => false,
    require     => Exec["wireguard-correct-address-${interface}"],
  }

  # Reconcile any out-of-band PSK rotation on a subsequent Puppet run.
  exec { "wireguard-reconcile-psks-${interface}":
    command   => [$helper_file, 'sync-config', $interface, $config_file],
    unless    => [[$helper_file, 'psks-match', $interface, $config_file]],
    logoutput => false,
    require   => Exec["wireguard-syncconf-${interface}"],
  }

  exec { "wireguard-apply-private-key-${interface}":
    command   => ['/usr/bin/wg', 'set', $interface, 'private-key', $private_key_file],
    unless    => [[$helper_file, 'key-matches', $interface, $private_key_file]],
    logoutput => false,
    require   => [Exec["wireguard-reconcile-psks-${interface}"], File[$public_key_file]],
  }
}
