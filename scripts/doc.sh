#!/usr/bin/env bash

set -euo pipefail

for f in pkg/*; do
  if [[ -d $f ]]; then
    i=$(basename $f)
    godoc2md github.com/andy2046/jwks/pkg/$i \
      > $GOPATH/src/github.com/andy2046/jwks/docs/$i.md
  fi
done;