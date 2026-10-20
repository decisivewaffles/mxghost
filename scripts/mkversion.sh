#!/bin/bash

if git describe --exact-match --tags HEAD >/dev/null 2>&1; then
    # on a tag: release build
    version=$(git describe --tags --exact-match)-1
else
    # dev build: bump patch, add ~git suffix
    base_version=$(git describe --tags --abbrev=0 2>/dev/null || echo "0.0.0")
    ncommits=$(git rev-list --count "${base_version}..HEAD" || git rev-list --count HEAD)
    sha=$(git rev-parse --short=7 HEAD)
    # bump last component of base_version by 1
    next=$(echo "$base_version" | awk -F. '{ $NF=$NF+1; print }' OFS=.)
    version="${next}~git${ncommits}.g${sha}"
    nmatchingdeb=$(grep -cF "(${version}-" debian/changelog)
    nextdebver=$(echo "$nmatchingdeb" | awk -F. '{ $NF=$NF+1; print }' OFS=.)
    version="${next}~git${ncommits}.g${sha}-${nextdebver}"
fi
echo ${version}
