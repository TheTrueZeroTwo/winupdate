# Troubleshooting

## One-liner fails

Try the older Windows PowerShell fallback from the README. Also check proxy, TLS inspection, DNS, and whether the raw URL is blocked.

## Menu opens but action fails

Confirm that the configured `WINUPDATE_BASEURL` exposes all required `.ps1` files directly as raw text.

## Scheduled task runs but does nothing

Check Task Scheduler history and review logs under `C:\ProgramData\WinUpdateMspHelper\Logs`.

If the task uses Winget, try creating the task as the current interactive user instead of `SYSTEM`.

## Wiki does not update

Check the Gitea Actions run for `sync-wiki.yml`. Confirm that Actions are enabled, the Gitea wiki is enabled, and either the runner already has Git credentials or the repo secrets `GITEA_WIKI_TOKEN` and optional `GITEA_WIKI_USER` can push to the Gitea `.wiki.git` repository.
