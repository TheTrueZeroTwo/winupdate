# Remote-Only Design

The helper is intentionally built around remote web execution.

## Rules

- `menu.ps1` is the only normal entry point.
- `menu.ps1` loads `Common.ps1` from the configured raw HTTPS URL.
- Menu actions call `Invoke-WumRemoteScript`, which loads the selected script from the same web source into memory.
- The scripts should not write repo `.ps1` files to the client computer.

## Allowed local persistence

The following local persistence is expected:

- logs under `C:\ProgramData\WinUpdateMspHelper\Logs`;
- JSON reports under `C:\ProgramData\WinUpdateMspHelper\Reports`;
- actual changes requested by the technician, such as Windows updates, Winget upgrades, scheduled tasks, repair actions, reboot actions, and Windows Update cache resets.

Scheduled tasks store an encoded PowerShell command as the task action. They do not store local copies of the repo scripts.
