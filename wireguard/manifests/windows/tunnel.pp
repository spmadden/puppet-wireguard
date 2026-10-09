# An independently managed WireGuard for Windows client tunnel.
# User-controlled: Puppet manages the encrypted profile, NOT the tunnel's
# presence in SCM; disconnect in WireGuard GUI removes the tunnel service.
# Always-on: Puppet ensures the service exists/runs on every agent run.
define wireguard::windows::tunnel (
  Enum['present', 'absent'] $ensure = 'present',
  Enum['always_on', 'user_controlled'] $mode = 'user_controlled',
  String[1] $server_public_key,
  String[1] $endpoint,
  Array[String[1], 1] $addresses = ['10.100.0.10/32'],
  Array[String[1], 1] $allowed_ips = ['10.100.0.0/24'],
  Array[String[1]] $dns = [],
  Optional[Integer[576, 9000]] $mtu = undef,
  Optional[Integer[0, 65535]] $persistent_keepalive = 25,
  Boolean $preshared_key = false,
) {
  # Safe to embed tunnel names as a CLI argument and a basename.
  if $title !~ /\A[a-zA-Z][a-zA-Z0-9_-]{0,31}\z/ {
    fail('WireGuard Windows tunnel name must be 1-32 safe alphanumeric/underscore/hyphen characters, starting with a letter')
  }

  # Prevent line-injection into the WireGuard INI; the profile contains only
  # public fields, but Windows WireGuard supports privileged script hooks.
  $profile_fields = $addresses + $allowed_ips + $dns + [$server_public_key, $endpoint]
  $profile_fields.each |String $field| {
    if $field =~ /[\r\n]/ {
      fail('WireGuard Windows profile values cannot contain newlines')
    }
  }

  include wireguard::windows

  $root = 'C:/ProgramData/WireGuardPuppet'
  $powershell = 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
  $helper = "${root}/manage.ps1"
  $profile = "${root}/Desired/${title}.conf"
  $psk_option = $preshared_key ? {
    true    => ' -RequirePSK',
    default => '',
  }

  if $ensure == 'present' {
    file { $profile:
      ensure  => file,
      content => epp('wireguard/windows/client.conf.epp', {
        'addresses'            => $addresses,
        'dns'                  => $dns,
        'mtu'                  => $mtu,
        'server_public_key'    => $server_public_key,
        'endpoint'             => $endpoint,
        'allowed_ips'          => $allowed_ips,
        'persistent_keepalive' => $persistent_keepalive,
      }),
      require => Class['wireguard::windows'],
    }

    exec { "wireguard-windows-apply-${title}":
      command => "\"${powershell}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"${helper}\" -Action Apply -Tunnel ${title} -Mode ${mode}${psk_option}",
      unless  => "\"${powershell}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"${helper}\" -Action Test -Tunnel ${title} -Mode ${mode}${psk_option}",
      timeout => 180,
      require => [File[$profile], Service['WireGuardManager']],
    }
  } else {
    file { $profile:
      ensure  => absent,
      require => Class['wireguard::windows'],
    }

    exec { "wireguard-windows-remove-${title}":
      command => "\"${powershell}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"${helper}\" -Action Remove -Tunnel ${title}",
      unless  => "\"${powershell}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"${helper}\" -Action Missing -Tunnel ${title}",
      timeout => 120,
      require => [File[$profile], Service['WireGuardManager']],
    }
  }
}
