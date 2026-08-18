param(
    [ValidateSet('Auto', 'OperaGX', 'Chrome', 'Edge', 'Chromium', 'Firefox', 'All')]
    [string]$Browser = 'Auto'
)

$ErrorActionPreference = 'Stop'
$hostName = 'org.privoke.runtime_launcher'
$supervisorRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $supervisorRoot '..\..')).Path
$extensionRoot = Join-Path $repositoryRoot 'extension'
$identityPath = Join-Path $extensionRoot 'extension-identities.json'
$pythonPath = Join-Path $extensionRoot 'client-runtime\.venv\Scripts\python.exe'
$sourceHostPath = Join-Path $supervisorRoot 'src\native_messaging_host.py'
$launcherSourcePath = Join-Path $supervisorRoot 'scripts\native-host-launcher.cs'

foreach ($requiredFile in @($identityPath, $pythonPath, $sourceHostPath, $launcherSourcePath)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required PriVoke file is missing: $requiredFile"
    }
}

$identities = Get-Content -Raw -LiteralPath $identityPath | ConvertFrom-Json
$chromiumExtensionId = [string]$identities.chromium_extension_id
$firefoxExtensionId = [string]$identities.firefox_extension_id
if ($chromiumExtensionId -notmatch '^[a-p]{32}$' -or -not $firefoxExtensionId) {
    throw "PriVoke extension identities are invalid: $identityPath"
}

function Get-DefaultBrowserFamily {
    $choicePath = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice'
    $progId = [string](Get-ItemProperty -Path $choicePath -ErrorAction SilentlyContinue).ProgId
    if ($progId -match 'Opera') { return 'OperaGX' }
    if ($progId -match 'Firefox') { return 'Firefox' }
    if ($progId -match 'MSEdge|Edge') { return 'Edge' }
    if ($progId -match 'Chrome') { return 'Chrome' }
    return 'All'
}

$selectedBrowser = if ($Browser -eq 'Auto') { Get-DefaultBrowserFamily } else { $Browser }
$installRoot = Join-Path $env:LOCALAPPDATA 'PriVoke\NativeHost'
New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
$installedHostPath = Join-Path $installRoot 'native_messaging_host.py'
$launcherPath = Join-Path $installRoot 'privoke-native-host.exe'
$launcherConfigPath = Join-Path $installRoot 'privoke-native-host.config'
$chromiumManifestPath = Join-Path $installRoot "$hostName.chromium.json"
$firefoxManifestPath = Join-Path $installRoot "$hostName.firefox.json"
Copy-Item -LiteralPath $sourceHostPath -Destination $installedHostPath -Force

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines(
    $launcherConfigPath,
    @($pythonPath, $installedHostPath, $repositoryRoot),
    $utf8NoBom
)
if (Test-Path -LiteralPath $launcherPath) {
    Remove-Item -LiteralPath $launcherPath -Force
}
$launcherSource = Get-Content -LiteralPath $launcherSourcePath -Raw
Add-Type -TypeDefinition $launcherSource -Language CSharp -OutputAssembly $launcherPath -OutputType WindowsApplication

$chromiumManifest = [ordered]@{
    name = $hostName
    description = 'Starts the workstation-local PriVoke runtime supervisor.'
    path = $launcherPath
    type = 'stdio'
    allowed_origins = @("chrome-extension://$chromiumExtensionId/")
} | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText($chromiumManifestPath, $chromiumManifest, $utf8NoBom)

$firefoxManifest = [ordered]@{
    name = $hostName
    description = 'Starts the workstation-local PriVoke runtime supervisor.'
    path = $launcherPath
    type = 'stdio'
    allowed_extensions = @($firefoxExtensionId)
} | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText($firefoxManifestPath, $firefoxManifest, $utf8NoBom)

$registrations = @()
if ($selectedBrowser -in @('OperaGX', 'Chrome', 'All')) {
    # Opera's documented Windows native-messaging lookup uses Chrome's registry root.
    $registrations += [pscustomobject]@{
        Browser = if ($selectedBrowser -eq 'OperaGX') { 'Opera GX' } else { 'Chrome / Opera GX' }
        Root = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts'
        Manifest = $chromiumManifestPath
    }
}
if ($selectedBrowser -in @('Edge', 'All')) {
    $registrations += [pscustomobject]@{
        Browser = 'Microsoft Edge'
        Root = 'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts'
        Manifest = $chromiumManifestPath
    }
}
if ($selectedBrowser -in @('Chromium', 'All')) {
    $registrations += [pscustomobject]@{
        Browser = 'Chromium'
        Root = 'HKCU:\Software\Chromium\NativeMessagingHosts'
        Manifest = $chromiumManifestPath
    }
}
if ($selectedBrowser -in @('Firefox', 'All')) {
    $registrations += [pscustomobject]@{
        Browser = 'Firefox'
        Root = 'HKCU:\Software\Mozilla\NativeMessagingHosts'
        Manifest = $firefoxManifestPath
    }
}

foreach ($registration in $registrations) {
    $key = Join-Path $registration.Root $hostName
    New-Item -Path $key -Force | Out-Null
    Set-Item -Path $key -Value $registration.Manifest
    $actual = (Get-Item $key).GetValue('')
    if ($actual -ne $registration.Manifest) {
        throw "Native host registration verification failed for $($registration.Browser)."
    }
    Write-Output "Registered $hostName for $($registration.Browser)."
}

Write-Output "Browser selection: $selectedBrowser"
Write-Output "Chromium-family extension ID: $chromiumExtensionId"
Write-Output "Firefox extension ID: $firefoxExtensionId"
Write-Output "Native host executable: $launcherPath"
Write-Output 'Fully exit and restart the browser, then reload the unpacked extension.'
