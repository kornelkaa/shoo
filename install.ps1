# Installs shoo on Windows, then starts `shoo setup`.
#
#   irm https://raw.githubusercontent.com/kornelkaa/shoo/main/install.ps1 | iex
#
# Run it in a normal PowerShell window, not as administrator. It downloads the
# latest release from GitHub, checks its SHA-256 checksum, puts shoo.exe in
# %ProgramFiles%\shoo (Windows asks you to confirm) and adds that folder to
# your PATH, then runs `shoo setup`, which asks a few questions.
# Run the same command again to update.

$ErrorActionPreference = 'Stop'
# Windows PowerShell's progress bar makes downloads many times slower.
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Quote puts a value in a single-quoted PowerShell string: a path with an
# apostrophe in it (C:\Users\O'Brien) would otherwise end the string early.
function Quote($s) { "'" + ($s -replace "'", "''") + "'" }

$repo = 'kornelkaa/shoo'
$base = if ($env:SHOO_BASE_URL) { $env:SHOO_BASE_URL } else { "https://github.com/$repo/releases/latest/download" }

function Fail($msg) { Write-Host "shoo install: $msg" -ForegroundColor Red; throw $msg }

$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
    'AMD64' { $goarch = 'amd64' }
    'ARM64' { $goarch = 'arm64' }
    default { Fail "shoo needs 64-bit Windows (this is $arch)." }
}
$asset = "shoo-windows-$goarch.zip"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host 'Downloading shoo...'
    $zip = Join-Path $tmp $asset
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $zip
    $sum = (Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset.sha256").Content
    if ($sum -is [byte[]]) { $sum = [Text.Encoding]::ASCII.GetString($sum) }
    $want = ($sum -split '\s+')[0].ToLower()
    $got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
    if (-not $want -or $want -ne $got) { Fail "checksum mismatch (expected $want, got $got); not installing." }

    Expand-Archive -Path $zip -DestinationPath $tmp
    $new = Join-Path $tmp 'shoo.exe'
    if (-not (Test-Path $new)) { Fail "the download doesn't contain shoo.exe." }
    & $new version | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "the downloaded shoo doesn't run on this PC." }
    $hash = (Get-FileHash -Algorithm SHA256 $new).Hash

    # shoo runs this file with admin rights during setup, so it goes where only
    # admins can change it. The admin step checks the file again after copying
    # it there, because anything running as you could change the temporary copy.
    # A running exe can't be replaced but can be renamed, so the old one moves
    # aside.
    $pf = [Environment]::GetFolderPath('ProgramFiles')
    $dir = Join-Path $pf 'shoo'
    $dest = Join-Path $dir 'shoo.exe'
    # The machine PATH is read and written as stored, without expanding names
    # like %SystemRoot% in it; [Environment]::SetEnvironmentVariable would
    # write it back with them expanded, changing every other entry.
    $step = @"
`$ErrorActionPreference = 'Stop'
`$dir = $(Quote $dir); `$dest = $(Quote $dest); `$new = $(Quote $new)
New-Item -ItemType Directory -Force -Path `$dir | Out-Null
Copy-Item -LiteralPath `$new -Destination "`$dest.new" -Force
if ((Get-FileHash -Algorithm SHA256 -LiteralPath "`$dest.new").Hash -ne '$hash') { Remove-Item -LiteralPath "`$dest.new"; exit 1 }
Remove-Item -LiteralPath "`$dest.old" -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath `$dest) { Move-Item -LiteralPath `$dest "`$dest.old" -Force }
Move-Item -LiteralPath "`$dest.new" `$dest -Force
Remove-Item -LiteralPath "`$dest.old" -Force -ErrorAction SilentlyContinue
`$key = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
`$path = `$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
if ((`$path -split ';') -notcontains `$dir) {
    Set-ItemProperty -Path `$key.PSPath -Name Path -Type ExpandString -Value (`$path.TrimEnd(';') + ';' + `$dir)
    # Tell running programs (Explorer, new terminals) the PATH changed.
    Add-Type -Namespace Shoo -Name Env -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, UIntPtr w, string l, uint f, uint t, out UIntPtr r);'
    `$r = [UIntPtr]::Zero
    [void][Shoo.Env]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]`$r)
}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($step))
    Write-Host "Installing to $dest (Windows will ask you to confirm)..."
    $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded
    if ($p.ExitCode -ne 0) { Fail 'installing failed.' }

    $version = & $dest version
    Write-Host "Installed $version."
    if (($env:Path -split ';') -notcontains $dir) { $env:Path = "$env:Path;$dir" }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($env:SHOO_NO_SETUP -eq '1') { return }

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if ($me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This window runs as administrator: open a normal one and run `shoo setup` to finish.'
    return
}
Write-Host ''
& $dest setup
