param(
    [ValidateSet('Ensure','Repair')]
    [string]$Mode = 'Ensure'
)

$ErrorActionPreference = 'Stop'
$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
$commonCode = (New-Object Net.WebClient).DownloadString("$baseUrl/Common.ps1")
. ([ScriptBlock]::Create($commonCode))

$log = Start-WumLog -Name 'winget'
try {
    Assert-WumAdmin
    Write-WumSection 'Winget / App Installer'

    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget -and $Mode -eq 'Ensure') {
        Write-WumStep "winget found: $($winget.Source)"
        & $winget.Source --version
        return
    }

    Write-WumWarn 'This installs or repairs Microsoft App Installer, which provides winget.exe.'
    Write-WumWarn 'Install packages are downloaded to TEMP and removed after installation.'

    $tempRoot = Join-Path $env:TEMP ('WinUpdateMspWinget-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

    try {
        $vclibs = Join-Path $tempRoot 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
        $xaml   = Join-Path $tempRoot 'Microsoft.UI.Xaml.2.8.x64.appx'
        $wingetBundle = Join-Path $tempRoot 'Microsoft.DesktopAppInstaller.msixbundle'

        Write-WumStep 'Downloading winget dependencies and App Installer bundle'
        Invoke-WebRequest -Uri 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -UseBasicParsing -OutFile $vclibs -ErrorAction Stop
        Invoke-WebRequest -Uri 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.8.6' -UseBasicParsing -OutFile (Join-Path $tempRoot 'Microsoft.UI.Xaml.2.8.6.nupkg') -ErrorAction Stop
        Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -UseBasicParsing -OutFile $wingetBundle -ErrorAction Stop

        Write-WumStep 'Extracting Microsoft.UI.Xaml dependency from NuGet package'
        $nupkg = Join-Path $tempRoot 'Microsoft.UI.Xaml.2.8.6.nupkg'
        $xamlExtract = Join-Path $tempRoot 'xaml'
        New-Item -ItemType Directory -Force -Path $xamlExtract | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($nupkg, $xamlExtract)
        $xamlCandidate = Get-ChildItem -Path $xamlExtract -Recurse -Filter 'Microsoft.UI.Xaml.2.8.appx' | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
        if ($xamlCandidate) { Copy-Item -Path $xamlCandidate.FullName -Destination $xaml -Force }

        Write-WumStep 'Installing VCLibs dependency'
        try { Add-AppxPackage -Path $vclibs -ErrorAction Stop } catch { Write-WumWarn "VCLibs install warning: $($_.Exception.Message)" }

        if (Test-Path $xaml) {
            Write-WumStep 'Installing Microsoft.UI.Xaml dependency'
            try { Add-AppxPackage -Path $xaml -ErrorAction Stop } catch { Write-WumWarn "Microsoft.UI.Xaml install warning: $($_.Exception.Message)" }
        } else {
            Write-WumWarn 'Microsoft.UI.Xaml x64 dependency was not found in the NuGet package. Continuing.'
        }

        Write-WumStep 'Installing Microsoft App Installer / winget'
        Add-AppxPackage -Path $wingetBundle -ForceApplicationShutdown -ErrorAction Stop
    } finally {
        try { Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }

    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
        Write-WumStep "winget installed: $($winget.Source)"
        & $winget.Source --version
        try { & $winget.Source source reset --force } catch { }
        try { & $winget.Source source update } catch { }
    } else {
        Write-WumWarn 'winget.exe is still not available. On some Windows images, the user must sign in once or Microsoft Store/App Installer policy must allow registration.'
    }
} finally {
    Stop-WumLog
}
