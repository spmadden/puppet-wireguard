# Common Windows client support. WireGuard for Windows must be installed first.
# This class deploys only public management code and enables the native GUI manager.
class wireguard::windows {
  $root = 'C:/ProgramData/WireGuardPuppet'
  $powershell = 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
  $manager_exe = 'C:/Program Files/WireGuard/wireguard.exe'

  file { $root:
    ensure => directory,
  }

  file { "${root}/Desired":
    ensure  => directory,
    require => File[$root],
  }

  file { "${root}/manage.ps1":
    ensure  => file,
    source  => 'puppet:///modules/wireguard/windows-manage.ps1',
    require => File[$root],
  }

  exec { 'wireguard-windows-install-manager':
    command => "\"${manager_exe}\" /installmanagerservice",
    unless  => "\"${powershell}\" -NoProfile -NonInteractive -Command \"if (Get-Service -Name 'WireGuardManager' -ErrorAction SilentlyContinue) {exit 0} else {exit 1}\"",
    require => File["${root}/manage.ps1"],
  }

  service { 'WireGuardManager':
    ensure  => running,
    enable  => true,
    require => Exec['wireguard-windows-install-manager'],
  }
}
