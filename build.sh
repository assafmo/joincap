#!/bin/bash

# build into ./release/
set -e
set -v

go test -race -cover ./...

rm -rf release
mkdir -p release

VERSION=$(git describe --tags $(git rev-list --tags --max-count=1))

# https://golang.org/doc/install/source#environment
GOOS=linux   GOARCH=amd64 go build -ldflags '-s -w' -o "release/joincap-linux64-${VERSION}"
GOOS=windows GOARCH=amd64 go build -ldflags '-s -w' -o "release/joincap-win64-${VERSION}.exe"
GOOS=darwin  GOARCH=amd64 go build -ldflags '-s -w' -o "release/joincap-macos64-${VERSION}"
GOOS=linux   GOARCH=arm64 go build -ldflags '-s -w' -o "release/joincap-linux-arm64-${VERSION}"

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
Installed-Size: $(ls -l --block-size=KB ./deb/bin/joincap | awk '{print $5}' | tr -d 'kB')
Description: Merge multiple pcap files together, gracefully.
EOF

    dpkg-deb --build ./deb/ .
    rm -rf ./deb
)