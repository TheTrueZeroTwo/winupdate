# One-Line Run

Open PowerShell as Administrator and run:

```powershell
$u='https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/menu.ps1'; $r='https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/README.md'; try { iex (irm $u) } catch { try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex ((New-Object Net.WebClient).DownloadString($u)) } catch { Write-Host "Failed to load menu. Open README: $r" -ForegroundColor Yellow; throw } }
```

The runtime source is GitHub raw only. Do not use the private mirror URL for MSP client machines because it requires login and blocks unauthenticated command-line web requests.

The command tries `Invoke-RestMethod` first. If that fails, it falls back to `WebClient.DownloadString`. If both methods fail, it prints the README URL so the technician can open instructions manually.
