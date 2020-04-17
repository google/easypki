#!/usr/bin/env bash

set -Eeuo pipefail

true > coverage.txt

for d in $(go list ./... | grep -v vendor); do
    go test -race -coverprofile=profile.out -covermode=atomic "$d"
    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm -f profile.out
    fi
done
