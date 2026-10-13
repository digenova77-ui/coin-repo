#!/usr/bin/env bash
# Pre-commit guard: refuse key-shaped material. Exit 1 = commit denied.
# Scans staged files EXCLUDING itself; targets secret FORMATS and
# secret-bearing FILENAMES, not prose about the doctrine.
set -u
fail=0
for f in $(git diff --cached --name-only --diff-filter=ACM); do
  case "$f" in
    *.pem|*.key|*.p12|*.keystore|*id_rsa*|*id_ed25519*|.env|.env.*|*wallet*.json|*mnemonic*)
      echo "GUARD: refused file: $f" >&2; fail=1;;
  esac
done
content=$(git diff --cached -U0 -- . ':(exclude)tools/guard.sh')
if printf '%s' "$content" | grep -E 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|xprv[0-9A-Za-z]{100,}|-----BEGIN PGP PRIVATE' >/dev/null 2>&1; then
  echo "GUARD: private-key material detected in staged changes" >&2; fail=1
fi
[ "$fail" -eq 1 ] && echo "The vault is not the town square. Commit denied." >&2
exit $fail
