#!/bin/bash

# build into ./release/
set -e
set -v

go get -v -u -t -d ./...

go test -race -cover ./...

rm -rf release
mkdir -p release

VERSION=$(git describe --tags $(git rev-list --tags --max-count=1))

# https://golang.org/doc/install/source#environment
GOOS=linux   GOARCH=amd64 go build -o "release/joincap-linux64-${VERSION}"
GOOS=windows GOARCH=amd64 go build -o "release/joincap-win64-${VERSION}.exe"
GOOS=darwin  GOARCH=amd64 go build -o "release/joincap-macos64-${VERSION}"

(
    # zip
    set -e
    cd release

    find -type f | 
    parallel --bar 'zip "$(echo "{}" | sed "s/.exe//").zip" "{}" && rm -f "{}"'

    # deb
    mkdir -p ./deb/bin
    unzip -o -d ./deb/bin joincap-linux64-*.zip
    mv -f ./deb/bin/joincap-linux64-* ./deb/bin/joincap

    mkdir -p ./deb/DEBIAN
    cat > ./deb/DEBIAN/control <<EOF 
Package: joincap
Version: $(echo "${VERSION}" | tr -d v)
Priority: optional
Architecture: amd64
Maintainer: Assaf Morami <assaf.morami@gmail.com>
Homepage: https://github.com/assafmo/joincap
Installed-Size: $(stat --printf="%s" ./deb/bin/joincap)
Provides: joincap
Conflicts: joincap
Replaces: joincap
Description: Merge multiple pcap files together, gracefully.
EOF

    dpkg-deb --build ./deb/ .
)