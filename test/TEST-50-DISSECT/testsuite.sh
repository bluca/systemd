#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

cd /tmp

image=$(mktemp -d -t -p /tmp tmp.XXXXXX)
if [ -z "${image}" ] || [ ! -d "${image}" ]; then
	echo "Could not create temporary directory with mktemp under /tmp"
	exit 1
fi

/usr/lib/systemd/systemd-dissect ${image}.raw | grep -q -F "Found read-only 'root' partition of type squashfs with verity"
/usr/lib/systemd/systemd-dissect ${image}.raw | grep -q -F -f /usr/lib/os-release

mv ${image}.verity ${image}.fooverity
mv ${image}.roothash ${image}.foohash
/usr/lib/systemd/systemd-dissect ${image}.raw --root-hash=`cat ${image}.foohash` --verity-data=${image}.fooverity | grep -q -F "Found read-only 'root' partition of type squashfs with verity"
/usr/lib/systemd/systemd-dissect ${image}.raw --root-hash=`cat ${image}.foohash` --verity-data=${image}.fooverity | grep -q -F -f /usr/lib/os-release

echo OK > /testok

exit 0
