#!/usr/bin/env bash
set -euo pipefail

# Local/manual helper for the same flow used by .gitea/workflows/sync-wiki.yml.
# Runtime/client PowerShell execution still uses GitHub raw URLs only.
# Optional environment variables:
#   WIKI_REPO_URL, WIKI_TOKEN, WIKI_USER, WIKI_DIR, WIKI_BRANCH, WIKI_COMMIT_MESSAGE

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WIKI_URL="${WIKI_REPO_URL:-https://gitthegit.zerotwo.tech/ZeroTwo/winupdate.wiki.git}"
WIKI_DIR="${WIKI_DIR:-WinUpdate.wiki}"
WIKI_BRANCH="${WIKI_BRANCH:-master}"
COMMIT_MESSAGE="${WIKI_COMMIT_MESSAGE:-Update WinUpdate wiki pages}"

cd "$ROOT_DIR"

if [ ! -d wiki ]; then
  echo "Missing wiki/ source directory." >&2
  exit 1
fi

AUTH_WIKI_URL="$WIKI_URL"
if [ -n "${WIKI_TOKEN:-}" ]; then
  if [ -z "${WIKI_USER:-}" ]; then
    echo "WIKI_USER must be the Gitea username that owns WIKI_TOKEN, not the token name." >&2
    exit 1
  fi
  USERNAME="$WIKI_USER"
  case "$WIKI_URL" in
    https://*) AUTH_WIKI_URL="https://${USERNAME}:${WIKI_TOKEN}@${WIKI_URL#https://}" ;;
    http://*)  AUTH_WIKI_URL="http://${USERNAME}:${WIKI_TOKEN}@${WIKI_URL#http://}" ;;
    *) echo "Unsupported wiki URL: $WIKI_URL" >&2; exit 1 ;;
  esac
fi

rm -rf "$WIKI_DIR"
initial_wiki_push=0

if git clone "$AUTH_WIKI_URL" "$WIKI_DIR"; then
  echo "Cloned existing wiki repository."
else
  echo "Could not clone wiki repository; trying first-time wiki initialization." >&2
  mkdir -p "$WIKI_DIR"
  git -C "$WIKI_DIR" init
  git -C "$WIKI_DIR" checkout -b "$WIKI_BRANCH"
  git -C "$WIKI_DIR" remote add origin "$AUTH_WIKI_URL"
  initial_wiki_push=1
fi

rsync -a --delete wiki/ "$WIKI_DIR"/
cd "$WIKI_DIR"
git add -A
if git diff --cached --quiet; then
  echo "Wiki is already up to date."
  exit 0
fi
git commit -m "$COMMIT_MESSAGE"
if [ "$initial_wiki_push" = "1" ]; then
  git push -u origin "HEAD:${WIKI_BRANCH}"
else
  git push
fi
