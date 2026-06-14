#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PS_FILES = sorted(ROOT.glob('*.ps1'))
REQUIRED_FILES = {
    'Common.ps1',
    'menu.ps1',
    'Invoke-WinUpdate.ps1',
    'Install-Winget.ps1',
    'DiskCheck.ps1',
    'Get-SystemSnapshot.ps1',
    'Get-EventSummary.ps1',
    'Get-NetworkInfo.ps1',
    'Test-NetworkConnectivity.ps1',
    'Repair-Windows.ps1',
    'Install-Task.ps1',
    'update-noreboot.ps1',
    'update-reboot.ps1',
}

REMOTE_ONLY_FORBIDDEN_PATTERNS = [
    r'DownloadFile\s*\(',
    r'Start-BitsTransfer\b',
    r'Out-File\b[^\n\r]*(\.ps1|menu\.ps1|Common\.ps1)',
    r'Set-Content\b[^\n\r]*(\.ps1|menu\.ps1|Common\.ps1)',
    r'Add-Content\b[^\n\r]*(\.ps1|menu\.ps1|Common\.ps1)',
    r'Copy-Item\b[^\n\r]*(\.ps1|menu\.ps1|Common\.ps1)',
    r'New-Item\b[^\n\r]*-ItemType\s+File[^\n\r]*(\.ps1|menu\.ps1|Common\.ps1)',
]


def fail(message: str) -> None:
    print(f'FAIL: {message}', file=sys.stderr)
    sys.exit(1)


def read(path: Path) -> str:
    return path.read_text(encoding='utf-8', errors='replace')


def main() -> None:
    if not PS_FILES:
        fail('No PowerShell scripts found at repository root.')

    names = {p.name for p in PS_FILES}
    missing = sorted(REQUIRED_FILES - names)
    if missing:
        fail(f'Missing required scripts: {", ".join(missing)}')

    if (ROOT / '.github').exists():
        fail('GitHub Actions .github directory must not be present. This repo uses .gitea/workflows only.')

    if not (ROOT / '.gitea' / 'workflows' / 'test.yml').is_file():
        fail('Missing .gitea/workflows/test.yml')
    if not (ROOT / '.gitea' / 'workflows' / 'sync-wiki.yml').is_file():
        fail('Missing .gitea/workflows/sync-wiki.yml')
    if not (ROOT / 'wiki' / 'Home.md').is_file():
        fail('Missing wiki/Home.md')

    private_host = 'gitthe' + 'git.zerotwo.tech'
    for path in PS_FILES:
        text = read(path)
        if private_host in text:
            fail(f'{path.relative_to(ROOT)} references the private host. Runtime source must be GitHub raw only.')

    readme = read(ROOT / 'README.md')
    if 'raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/menu.ps1' not in readme:
        fail('README does not use the GitHub raw menu URL.')
    if 'menu.ps1' not in readme or 'README.md' not in readme or 'try { iex (irm $u)' not in readme:
        fail('README does not include the one-liner with menu and README fallback.')
    if 'private Gitea' not in readme and 'GitHub raw only' not in readme:
        fail('README should document why runtime uses GitHub raw only.')

    common = read(ROOT / 'Common.ps1')
    if 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' not in common:
        fail('Common.ps1 default base URL must be GitHub raw.')
    for required in REQUIRED_FILES - {'update-noreboot.ps1', 'update-reboot.ps1'}:
        if required not in common:
            fail(f'Common.ps1 allow-list does not mention {required}')

    menu = read(ROOT / 'menu.ps1')
    for script in [
        'Invoke-WinUpdate.ps1', 'Install-Winget.ps1', 'DiskCheck.ps1', 'Get-SystemSnapshot.ps1',
        'Get-EventSummary.ps1', 'Get-NetworkInfo.ps1', 'Test-NetworkConnectivity.ps1',
        'Repair-Windows.ps1', 'Install-Task.ps1'
    ]:
        if script not in menu:
            fail(f'menu.ps1 does not reference {script}')

    expected_menu_parameter_calls = [
        "'1' { Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ RebootMode = 'Never' }",
        "'2' { Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ RebootMode = 'IfNeeded' }",
        "'3' { Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ RebootMode = 'Never'; IncludeWinget = $true; InstallWingetIfMissing = $true }",
        "'4' { Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ SkipWindowsUpdate = $true; IncludeWinget = $true; InstallWingetIfMissing = $true }",
        "'5' { Invoke-WumRemoteScript -Name 'Install-Winget.ps1' -Parameters @{ Mode = 'Repair' }",
    ]
    for expected_call in expected_menu_parameter_calls:
        if expected_call not in menu:
            fail(f'menu is missing corrected named-parameter call: {expected_call}')

    if "-ArgumentList @('-RebootMode'" in menu or "-ArgumentList @('-Mode'" in menu:
        fail('menu options 1-5 must not pass named parameters through a string ArgumentList.')

    if '[hashtable]$Parameters' not in common or 'ConvertTo-WumParameterHashtable' not in common:
        fail('Common.ps1 must support hashtable parameter splatting and backward-compatible ArgumentList conversion.')

    if not re.search(r'Set-ExecutionPolicy\s+-Scope\s+Process\s+-ExecutionPolicy\s+Bypass', common, re.IGNORECASE):
        fail('Common.ps1 must set execution policy to Bypass at Process scope only.')
    if re.search(r'Set-ExecutionPolicy\s+-Scope\s+(LocalMachine|CurrentUser)', common, re.IGNORECASE):
        fail('Common.ps1 must not persistently change LocalMachine or CurrentUser execution policy.')

    update_script = read(ROOT / 'Invoke-WinUpdate.ps1')
    if 'Set-WumProcessExecutionPolicy' not in update_script:
        fail('Invoke-WinUpdate.ps1 must request process-only execution-policy setup.')
    if "Invoke-WumRemoteScript -Name 'Install-Winget.ps1' -ArgumentList" in update_script:
        fail('Invoke-WinUpdate.ps1 must use named hashtable parameters for Install-Winget.ps1.')

    install_task = read(ROOT / 'Install-Task.ps1')
    if '-EncodedCommand' not in install_task:
        fail('Install-Task.ps1 should register an encoded remote-run command, not local script files.')
    if 'Register-ScheduledTask' not in install_task:
        fail('Install-Task.ps1 does not register a scheduled task.')
    if 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' not in install_task:
        fail('Install-Task.ps1 default base URL must be GitHub raw.')

    if "Invoke-WumRemoteScript -Name '$scriptName' -Parameters $parametersExpr" not in install_task:
        fail('Install-Task.ps1 scheduled payload must invoke remote scripts with -Parameters.')

    network = read(ROOT / 'Test-NetworkConnectivity.ps1')
    if 'Read-Host' not in network or 'Target' not in network:
        fail('Test-NetworkConnectivity.ps1 should ask for target IPs/hostnames.')

    test_workflow = read(ROOT / '.gitea' / 'workflows' / 'test.yml')
    wiki_workflow = read(ROOT / '.gitea' / 'workflows' / 'sync-wiki.yml')
    if 'python3 tools/test_repository.py' not in test_workflow:
        fail('test.yml should run tools/test_repository.py')
    if 'tests/Test-Repository.ps1' not in test_workflow:
        fail('test.yml should run PowerShell parser tests')
    if 'pwsh -NoProfile -ExecutionPolicy Bypass -File tests/Test-Repository.ps1' not in test_workflow:
        fail('test.yml should run the PowerShell AST/parser test after installing pwsh')

    if 'gitthegit.zerotwo.tech/ZeroTwo/winupdate.wiki.git' not in wiki_workflow:
        fail('sync-wiki.yml should push to the explicit Gitea wiki repo URL.')
    for required in ['git clone', 'rsync -a --delete wiki/', 'git add -A', 'git commit -m "Update WinUpdate wiki pages"', 'git push']:
        if required not in wiki_workflow:
            fail(f'sync-wiki.yml is missing wiki automation step: {required}')
    if 'WIKI_TOKEN' not in wiki_workflow:
        fail('sync-wiki.yml should support WIKI_TOKEN for authenticated wiki push.')
    if 'GITEA_WIKI_TOKEN' in wiki_workflow or 'GITEA_WIKI_USER' in wiki_workflow:
        fail('sync-wiki.yml should use WIKI_TOKEN and WIKI_USER, not secret/env names starting with GITEA_.')

    sync_helper_path = ROOT / 'tools' / 'Sync-GiteaWiki.sh'
    if sync_helper_path.is_file():
        sync_helper = read(sync_helper_path)
        for required in ['git clone', 'rsync -a --delete wiki/', 'git add -A', 'git commit -m "$COMMIT_MESSAGE"', 'git push']:
            if required not in sync_helper:
                fail(f'tools/Sync-GiteaWiki.sh is missing wiki automation step: {required}')
        if 'GITEA_WIKI_TOKEN' in sync_helper or 'GITEA_WIKI_USER' in sync_helper:
            fail('tools/Sync-GiteaWiki.sh should use WIKI_TOKEN and WIKI_USER, not GITEA_ variable names.')

    for path in PS_FILES:
        text = read(path)
        for pattern in REMOTE_ONLY_FORBIDDEN_PATTERNS:
            if re.search(pattern, text, flags=re.IGNORECASE):
                fail(f'{path.name} appears to save repo scripts locally; matched {pattern!r}')

    print(f'PASS: checked {len(PS_FILES)} PowerShell scripts, Gitea workflows, GitHub-only runtime URLs, WIKI_TOKEN/WIKI_USER wiki sync automation, README, wiki source, scheduled task, process-only execution policy, and remote-only rules.')


if __name__ == '__main__':
    main()
