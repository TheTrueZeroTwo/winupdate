# CI and Wiki Automation

The repo includes Gitea Actions workflows under `.gitea/workflows`.

The important split is:

- Client/runtime PowerShell execution uses GitHub raw URLs only.
- Gitea Actions can use the private Gitea server for repository automation, including wiki updates.

## `test.yml`

Runs static tests for:

- required script files;
- README one-liner fallback;
- GitHub-only runtime URL rules;
- menu references;
- scheduled task implementation;
- Network/VPN input behavior;
- remote-only rule checks;
- optional PowerShell AST parser checks when `pwsh` is installed on the runner.

## `sync-wiki.yml`

Runs when scripts, README, workflow, tools, or `wiki/` files change. It automates the same flow as the manual wiki update command:

```bash
git clone https://gitthegit.zerotwo.tech/ZeroTwo/winupdate.wiki.git WinUpdate.wiki
rsync -a --delete wiki/ WinUpdate.wiki/
cd WinUpdate.wiki
git add -A
git commit -m "Update WinUpdate wiki pages"
git push
```

The workflow skips the commit if there are no wiki changes.

Required Gitea secret when the runner does not already have push credentials:

- `GITEA_WIKI_TOKEN` — token/password with write access to the wiki repo.

Optional Gitea secret:

- `GITEA_WIKI_USER` — username for the token. If omitted, the workflow uses the Actions actor.

The wiki source is the `wiki/` directory in the main repo. Edit those files, not the generated wiki repo directly.
