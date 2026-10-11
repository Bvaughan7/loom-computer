#!/usr/bin/env bash
# Cut a Loom Computer release: ./scripts/release.sh [--dry-run] [--yes] <version>
#
#   <version>   semver X.Y.Z (no leading v)
#   --dry-run   build the image locally as ghcr.io/bvaughan7/loom-computer:<version>
#               and check that it serves <version> in its guide. Touches no
#               git state and pushes nothing. <version> may be omitted (uses VERSION).
#   --yes       skip the confirmation prompt
#
# A real run: validates, writes VERSION, commits, tags v<version> and pushes
# the tag. CI (.github/workflows/release.yml) builds, pushes to GHCR and
# creates the GitHub release from the tag.
set -euo pipefail

IMAGE="ghcr.io/bvaughan7/loom-computer"
DOCKER="${DOCKER:-docker}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

dry_run=0 assume_yes=0 version=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --yes|-y) assume_yes=1 ;;
    -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *) [ -z "$version" ] || { echo "only one version allowed" >&2; exit 2; }; version="$arg" ;;
  esac
done

current="$(tr -d '[:space:]' < VERSION)"
if [ -z "$version" ] && [ "$dry_run" = 1 ]; then version="$current"; fi
[ -n "$version" ] || { echo "usage: $0 [--dry-run] [--yes] <version>" >&2; exit 2; }
if ! printf '%s' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "not a plain semver X.Y.Z version (no 'v' prefix, no pre-release): $version" >&2
  exit 2
fi
ref="$IMAGE:$version"

tmp="" cid=""   # globals: the EXIT trap runs after the function returns
dry_run_build() {
  local out
  tmp="$(mktemp -d)"
  cid=""
  trap '[ -z "$cid" ] || "$DOCKER" rm -f "$cid" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
  # Build from a copy of the working tree with VERSION set to the requested
  # version, so a dry run works before VERSION is bumped and changes nothing.
  git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$tmp"
  printf '%s\n' "$version" > "$tmp/VERSION"
  echo "dry run: building $ref"
  "$DOCKER" build --build-arg "VERSION=$version" -t "$ref" "$tmp"
  cid="$("$DOCKER" run -d -e LOOM_COMPUTER_TOKEN=dry-run "$ref")"
  for _ in $(seq 60); do
    "$DOCKER" exec "$cid" python -c \
      'import urllib.request as u; u.urlopen("http://127.0.0.1:8787/health", timeout=1)' \
      >/dev/null 2>&1 && break
    sleep 1
  done
  out="$("$DOCKER" exec "$cid" python -c '
import json, urllib.request as u
req = u.Request("http://127.0.0.1:8787/mcp", headers={
    "Authorization": "Bearer dry-run", "Content-Type": "application/json"},
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "state", "arguments": {"action": "guide"}}}).encode())
print(json.load(u.urlopen(req, timeout=10))["result"]["structuredContent"]["version"])')"
  if [ "$out" != "$version" ]; then
    echo "FAIL: image guide serves '$out', expected '$version'" >&2
    exit 1
  fi
  echo "ok: $ref serves guide version $out (nothing pushed)"
}

if [ "$dry_run" = 1 ]; then
  dry_run_build
  exit 0
fi

# --- real release ---
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean" >&2; exit 1; }
tag="v$version"
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "tag $tag already exists" >&2; exit 1
fi
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
  echo "tag $tag already exists on origin" >&2; exit 1
fi

echo "release $tag: image $ref (from branch $(git rev-parse --abbrev-ref HEAD))"
if [ "$assume_yes" != 1 ]; then
  read -r -p "write VERSION, commit, tag and push $tag? [y/N] " ans
  [ "$ans" = y ] || [ "$ans" = Y ] || { echo "aborted"; exit 1; }
fi

if [ "$version" != "$current" ]; then
  printf '%s\n' "$version" > VERSION
  git add VERSION
  git commit -m "release: $version"
fi
git tag -a "$tag" -m "Loom Computer $version"
git push origin "$tag"

cat <<MSG

Tag $tag pushed. CI builds and pushes $ref, then creates the GitHub release.
Watch it:  gh run list --workflow release.yml

The package is private. To pull it (or let the desk's host pull it):
  echo "\$GHCR_PAT" | docker login ghcr.io -u <github-user> --password-stdin
  (classic PAT: read:packages to pull, write:packages to push manually)
MSG
