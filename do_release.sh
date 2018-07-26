#!/bin/bash

rm -rf release
mkdir -p release

VERSION=$(git tag | tail -1)

# https://golang.org/doc/install/source#environment
GOOS=linux   GOARCH=amd64 go build -o "release/joincap-linux64-${VERSION}"
GOOS=windows GOARCH=amd64 go build -o "release/joincap-win64-${VERSION}.exe"
GOOS=darwin  GOARCH=amd64 go build -o "release/joincap-macos64-${VERSION}"

(
    cd release
    find -type f | 
    parallel --bar 'zip "$(echo "{}" | sed "s/.exe//").zip" "{}" && rm -f "{}"'
)

# snap

snapcraft
snapcraft push *.snap
snapcraft list-revisions joincap
REV=$(snapcraft list-revisions joincap | head -2 | tail -1 | awk '{print $1}')
snapcraft release joincap "$REV" stable