#Requires -Version 5.1
<#
WireGuard for Windows, controlled by the Puppet agent (LocalSystem).

Actions:
  Test    exit 0 if configuration and requested operating mode are reconciled
  Apply   generate local identity (once), consume PSK enrollment, provision DPAPI config
  Missing exit 0 if removed
  Remove  uninstall tunnel and remove its config, preserve client identity and PSK

No private key, PSK, or plaintext complete tunnel configuration is written to
Puppet manifests, catalogs, reports, command lines, or persistent plaintext files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Test','Apply','Missing','Remove')]
    [string]$Action,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[A-Za-z][A-Za-z0-9_-]{0,31}$')]
    [string]$Tunnel,

    [ValidateSet('always_on','user_controlled')]
    [string]$Mode = 'user_controlled',

    [switch]$RequirePSK
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# All secret material is protected for the LocalSystem user account, rather than
# by machine-wide DPAPI. A normal administrative PowerShell console is not a
# valid replacement for the LocalSystem Puppet agent.
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
    throw 'Run this helper as LocalSystem (the Puppet agent account).'
}

$Root = Join-Path $env:ProgramData 'WireGuardPuppet'
$Secrets = Join-Path $Root 'Secrets'
$Desired = Join-Path $Root "Desired\$Tunnel.conf"
$PrivateBlob = Join-Path $Secrets "$Tunnel.private.dpapi"
$PSKBlob = Join-Path $Secrets "$Tunnel.psk.dpapi"
$PSKImport = Join-Path $Secrets "$Tunnel.psk.import"
$PublicDir = Join-Path $Root 'PublicKeys'
$PublicFile = Join-Path $PublicDir "$Tunnel.pub"
$ConfigDir = Join-Path $env:ProgramFiles 'WireGuard\Data\Configurations'
$EncryptedConfig = Join-Path $ConfigDir "$Tunnel.conf.dpapi"
$WireGuard = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
$Wg = Join-Path $env:ProgramFiles 'WireGuard\wg.exe'
$ServiceName = 'WireGuardTunnel$' + $Tunnel

# WireGuard's DPAPI .conf.dpapi format requires a description matching the
# tunnel name, not just generic ProtectedData.Protect() output. This code uses
# the same CryptProtectData/CryptUnprotectData APIs and description convention
# as WireGuard for Windows. No CRYPTPROTECT_LOCAL_MACHINE flag is used.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WireGuardConfigDPAPI {
    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public int Size; public IntPtr Data; }

    [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input, string description,
        IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref Blob output);

    [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input, out IntPtr description,
        IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref Blob output);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    private static Blob Allocate(byte[] data) {
        Blob b = new Blob();
        b.Size = data.Length;
        b.Data = Marshal.AllocHGlobal(Math.Max(data.Length, 1));
        if (data.Length > 0) Marshal.Copy(data, 0, b.Data, data.Length);
        return b;
    }

    private static byte[] CopyOut(Blob b) {
        byte[] value = new byte[b.Size];
        if (b.Size > 0) Marshal.Copy(b.Data, value, 0, b.Size);
        return value;
    }

    public static byte[] Protect(byte[] plain, string name) {
        Blob input = Allocate(plain), output = new Blob();
        try {
            if (!CryptProtectData(ref input, name, IntPtr.Zero, IntPtr.Zero,
                  IntPtr.Zero, 1, ref output))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return CopyOut(output);
        } finally {
            Marshal.FreeHGlobal(input.Data);
            if (output.Data != IntPtr.Zero) LocalFree(output.Data);
        }
    }

    public static byte[] Unprotect(byte[] encrypted, string name) {
        Blob input = Allocate(encrypted), output = new Blob();
        IntPtr description = IntPtr.Zero;
        try {
            if (!CryptUnprotectData(ref input, out description, IntPtr.Zero,
                  IntPtr.Zero, IntPtr.Zero, 1, ref output))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (description == IntPtr.Zero ||
                !string.Equals(Marshal.PtrToStringUni(description), name,
                  StringComparison.Ordinal))
                throw new InvalidOperationException("WireGuard DPAPI tunnel name mismatch");
            return CopyOut(output);
        } finally {
            Marshal.FreeHGlobal(input.Data);
            if (output.Data != IntPtr.Zero) LocalFree(output.Data);
            if (description != IntPtr.Zero) LocalFree(description);
        }
    }
}
'@ -ErrorAction Stop

function Assert-Key([string]$Text) {
    $key = $Text.Trim()
    try { $decoded = [Convert]::FromBase64String($key) }
    catch { throw 'Invalid base64-encoded WireGuard key' }
    if ($decoded.Length -ne 32) { throw 'WireGuard key must encode 32 bytes' }
    return $key
}

function Get-ServiceIfPresent {
    return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Invoke-WireGuard([string[]]$ToolArgs) {
    if (-not (Test-Path -LiteralPath $WireGuard)) {
        throw 'WireGuard for Windows is not installed'
    }
    $output = (& $WireGuard @ToolArgs 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "wireguard.exe failed: $output" }
}

function Wait-Until-ServiceRemoved {
    for ($i = 0; $i -lt 80; $i++) {
        if (-not (Get-ServiceIfPresent)) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Timed out waiting for $ServiceName to be deleted"
}

function Remove-TunnelService {
    if (Get-ServiceIfPresent) {
        Invoke-WireGuard -ToolArgs @('/uninstalltunnelservice', $Tunnel)
        Wait-Until-ServiceRemoved
    }
}

function Protect-LocalSecret([string]$Plain, [string]$Path) {
    $bytes = [Text.Encoding]::ASCII.GetBytes((Assert-Key $Plain) + "`n")
    $sealed = [Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $tmp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllBytes($tmp, $sealed)
        if (Test-Path -LiteralPath $Path) {
            [IO.File]::Replace($tmp, $Path, $null)
        } else {
            [IO.File]::Move($tmp, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    }
}

function Unprotect-LocalSecret([string]$Path) {
    $sealed = [IO.File]::ReadAllBytes($Path)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $sealed, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    return Assert-Key ([Text.Encoding]::ASCII.GetString($plain))
}

function Initialize-SecureStorage {
    foreach ($dir in @($Root, $Secrets)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force)
        }
        if ((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Refusing reparse-point directory: $dir"
        }
        # Explicit ACLs, irrespective of localized Windows account names.
        & "$env:SystemRoot\System32\icacls.exe" $dir /inheritance:r `
            /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to secure directory ACL: $dir" }
    }
    if (-not (Test-Path -LiteralPath $PublicDir)) {
        [void](New-Item -ItemType Directory -Path $PublicDir -Force)
    }
}

function Get-Identity([bool]$Create) {
    if (Test-Path -LiteralPath $PrivateBlob) {
        return Unprotect-LocalSecret $PrivateBlob
    }
    if (-not $Create) { return $null }
    # Do not silently rotate a client identity if an existing WireGuard
    # configuration is still present but the separately protected key is lost.
    if (Test-Path -LiteralPath $EncryptedConfig) {
        throw 'Existing encrypted tunnel configuration but missing local private key. Restore the key; refusing identity rotation.'
    }
    if (-not (Test-Path -LiteralPath $Wg)) { throw 'wg.exe is not installed' }
    $new = (& $Wg genkey | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'wg genkey failed' }
    $new = Assert-Key $new
    Protect-LocalSecret $new $PrivateBlob
    return $new
}

function Get-PSK([bool]$Import) {
    if ($RequirePSK -and $Import -and (Test-Path -LiteralPath $PSKImport)) {
        # This is an explicitly provisioned copy of the SERVER's PSK.
        # Do not generate a new independent PSK on the Windows client.
        $imported = Assert-Key ([IO.File]::ReadAllText($PSKImport))
        Protect-LocalSecret $imported $PSKBlob
        Remove-Item -LiteralPath $PSKImport -Force
    }
    if (-not $RequirePSK) { return $null }
    if (-not (Test-Path -LiteralPath $PSKBlob)) {
        if ($Import) { throw "Missing PSK: securely stage $PSKImport and run Puppet again" }
        return $null
    }
    return Unprotect-LocalSecret $PSKBlob
}

function Get-FullConfiguration([string]$Private, [string]$PSK) {
    if (-not (Test-Path -LiteralPath $Desired)) {
        throw "Missing Puppet-managed public profile: $Desired"
    }
    $profile = [IO.File]::ReadAllText($Desired)
    if ($profile -match '(?m)^\s*(PrivateKey|PresharedKey|PreUp|PostUp|PreDown|PostDown)\s*=') {
        throw 'Public profile must not contain key values or script execution hooks'
    }
    if (($profile | Select-String -Pattern '(?m)^\[Interface\]\r?$' -AllMatches).Matches.Count -ne 1 -or
        ($profile | Select-String -Pattern '(?m)^\[Peer\]\r?$' -AllMatches).Matches.Count -ne 1) {
        throw 'Expected exactly one [Interface] and one [Peer] section'
    }
    # Minimal fail-closed validation of the public fields (Windows WireGuard
    # has no supported config-validation-only CLI for an offline tunnel).
    $publicMatch = [regex]::Match($profile, '(?m)^PublicKey\s*=\s*([^\r\n]+)')
    if (-not $publicMatch.Success) { throw 'Peer PublicKey missing' }
    [void](Assert-Key $publicMatch.Groups[1].Value)
    foreach ($field in @('Address', 'AllowedIPs')) {
        $match = [regex]::Match($profile, '(?m)^' + $field + '\s*=\s*([^\r\n]+)')
        if (-not $match.Success) { throw "$field missing" }
        foreach ($cidr in ($match.Groups[1].Value -split ',')) {
            $parts = $cidr.Trim() -split '/'
            if ($parts.Count -ne 2 -or $parts[1] -notmatch '^\d{1,3}$') {
                throw "Invalid $field CIDR notation"
            }
            $ip = $null
            if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$ip)) {
                throw "Invalid $field IP address"
            }
            $max = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
            if ([int]$parts[1] -gt $max) { throw "Invalid $field prefix length" }
        }
    }
    $full = $profile -replace '(?m)^\[Interface\]\r?$', ("[Interface]`nPrivateKey = " + $Private)
    if ($PSK) {
        $full = $full -replace '(?m)^\[Peer\]\r?$', ("[Peer]`nPresharedKey = " + $PSK)
    }
    return $full
}

function Get-PublicKey([string]$Private) {
    if (-not (Test-Path -LiteralPath $Wg)) { throw 'wg.exe is not installed' }
    $key = (($Private + "`n") | & $Wg pubkey | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'wg pubkey failed' }
    return Assert-Key $key
}

function ConfigMatches([string]$Full) {
    if (-not (Test-Path -LiteralPath $EncryptedConfig)) { return $false }
    # Detect manual edits to WireGuard's encrypted store, not just changes to
    # Puppet's public profile. Decrypted content is never written to disk.
    $cipher = [IO.File]::ReadAllBytes($EncryptedConfig)
    $plain = [WireGuardConfigDPAPI]::Unprotect($cipher, $Tunnel)
    $existing = [Text.Encoding]::UTF8.GetString($plain)
    return ($existing -ceq $Full)
}

function Write-WireGuardEncryptedBytes([byte[]]$Cipher) {
    if (-not (Test-Path -LiteralPath $ConfigDir)) {
        throw "WireGuard manager configuration directory missing: $ConfigDir"
    }
    $tmp = Join-Path $ConfigDir ('.' + $Tunnel + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($tmp, $Cipher)
        & "$env:SystemRoot\System32\icacls.exe" $tmp /inheritance:r `
            /grant:r '*S-1-5-18:F' '*S-1-5-32-544:D' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to secure tunnel configuration ACL' }
        if (Test-Path -LiteralPath $EncryptedConfig) {
            [IO.File]::Replace($tmp, $EncryptedConfig, $null)
        } else {
            [IO.File]::Move($tmp, $EncryptedConfig)
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    }
}

function Write-WireGuardConfiguration([string]$Full) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Full)
    $cipher = [WireGuardConfigDPAPI]::Protect($bytes, $Tunnel)
    Write-WireGuardEncryptedBytes $cipher
}

function Ensure-AlwaysOn {
    $svc = Get-ServiceIfPresent
    if ($null -eq $svc) {
        Invoke-WireGuard -ToolArgs @('/installtunnelservice', $EncryptedConfig)
        $svc = Get-ServiceIfPresent
        if ($null -eq $svc) { throw "Tunnel service was not created: $ServiceName" }
    }
    Set-Service -Name $ServiceName -StartupType Automatic
    if ($svc.Status -ne 'Running') {
        Start-Service -Name $ServiceName
    }
    $svc = Get-ServiceIfPresent
    if ($svc.Status -ne 'Running') { throw "Tunnel is not running: $ServiceName" }
}

function Is-AlwaysOnSatisfied {
    $svc = Get-ServiceIfPresent
    if ($null -eq $svc -or $svc.Status -ne 'Running') { return $false }
    $cim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    return ($null -ne $cim -and $cim.StartMode -eq 'Auto')
}

try {
    if ($Action -eq 'Missing') {
        if ((Get-ServiceIfPresent) -or (Test-Path -LiteralPath $EncryptedConfig)) { exit 1 }
        exit 0
    }

    if ($Action -eq 'Remove') {
        Remove-TunnelService
        if (Test-Path -LiteralPath $EncryptedConfig) {
            Remove-Item -LiteralPath $EncryptedConfig -Force
        }
        # Deliberately retain *.private.dpapi, *.psk.dpapi and public key.
        exit 0
    }

    if ($Action -eq 'Test') {
        if (-not (Test-Path -LiteralPath $PrivateBlob)) { exit 1 }
        if ($RequirePSK -and (Test-Path -LiteralPath $PSKImport)) { exit 1 }
        $private = Get-Identity $false
        $psk = Get-PSK $false
        if ($RequirePSK -and -not $psk) { exit 1 }
        if (-not $private) { exit 1 }
        $full = Get-FullConfiguration $private $psk
        if (-not (ConfigMatches $full)) { exit 1 }
        if ($Mode -eq 'always_on' -and -not (Is-AlwaysOnSatisfied)) { exit 1 }
        exit 0
    }

    if (-not (Test-Path -LiteralPath $WireGuard)) {
        throw 'Install the signed WireGuard for Windows package before Puppet applies this resource'
    }
    Initialize-SecureStorage
    $private = Get-Identity $true
    # Publish the client public key even when PSK enrollment is still pending.
    $public = Get-PublicKey $private
    if ((-not (Test-Path -LiteralPath $PublicFile)) -or
        (([IO.File]::ReadAllText($PublicFile)).Trim() -cne $public)) {
        [IO.File]::WriteAllText($PublicFile, ($public + "`r`n"), [Text.Encoding]::ASCII)
    }

    $psk = Get-PSK $true
    $full = Get-FullConfiguration $private $psk
    if (-not (ConfigMatches $full)) {
        $svc = Get-ServiceIfPresent
        $wasActive = ($null -ne $svc -and $svc.Status -eq 'Running')
        $previousCipher = $null
        if (Test-Path -LiteralPath $EncryptedConfig) {
            $previousCipher = [IO.File]::ReadAllBytes($EncryptedConfig)
        }
        try {
            if ($null -ne $svc) { Remove-TunnelService }
            Write-WireGuardConfiguration $full
            # Preserve a user's connected/disconnected state when updating the
            # profile. The always-on mode intentionally overrides a disconnect.
            if ($Mode -eq 'always_on' -or $wasActive) {
                Ensure-AlwaysOn
            }
        } catch {
            $original = $_
            # Attempt to restore the last known encrypted configuration and
            # the previous connection state. The original error still fails
            # the Puppet run even if recovery succeeds.
            try {
                Remove-TunnelService
                if ($null -ne $previousCipher) {
                    Write-WireGuardEncryptedBytes $previousCipher
                    if ($wasActive) { Ensure-AlwaysOn }
                } elseif (Test-Path -LiteralPath $EncryptedConfig) {
                    Remove-Item -LiteralPath $EncryptedConfig -Force
                }
            } catch {
                [Console]::Error.WriteLine("WireGuard rollback failed: $($_.Exception.Message)")
            }
            throw $original
        }
    } elseif ($Mode -eq 'always_on') {
        Ensure-AlwaysOn
    }

    # In user_controlled mode, do NOT create or start a service merely because
    # its WireGuard profile exists. The GUI owns that transition.
    exit 0
} catch {
    # Exceptions contain only filenames / operations, never key material.
    [Console]::Error.WriteLine("WireGuard $Tunnel ($Action): $($_.Exception.Message)")
    exit 1
}
