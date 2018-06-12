#!/bin/bash

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo '# Changelog' > "${ROOT_DIR}/CHANGELOG.md"

git log --decorate | 
    sed -r 's/.*?tag: ([0-9.v]+).*/## \1/' | 
    awk '/##/{printf $0} /Date:/{print " ("$3,$4",",$6")"} /^ /{print "-"$0}' | 
    sed 's/    / /' | 
    grep -vP '^ \(' | 
    grep -vP '^[ -]+v' |
    sed -r 's/##/\n##/' >> "${ROOT_DIR}/CHANGELOG.md"