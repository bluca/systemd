#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

portablectl attach --now --runtime /usr/share/minimal_0.raw minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-foo.service
set +o pipefail
set +e
systemctl is-active minimal-app0-bar.service && exit 1
set -e
set -o pipefail

portablectl reattach --now --runtime /usr/share/minimal_1.raw minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-bar.service
set +o pipefail
set +e
systemctl is-active minimal-app0-foo.service && exit 1
set -e
set -o pipefail

portablectl list | grep -q -F "minimal_1"

portablectl detach --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl list | grep -q -F "No images."

# portablectl also works with directory paths rather than images

unsquashfs -dest /tmp/minimal_0 /usr/share/minimal_0.raw
unsquashfs -dest /tmp/minimal_1 /usr/share/minimal_1.raw

portablectl attach --copy=symlink --now --runtime /tmp/minimal_0 minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-foo.service
set +o pipefail
set +e
systemctl is-active minimal-app0-bar.service && exit 1
set -e
set -o pipefail

portablectl reattach --now --enable --runtime /tmp/minimal_1 minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-bar.service
set +o pipefail
set +e
systemctl is-active minimal-app0-foo.service && exit 1
set -e
set -o pipefail

portablectl list | grep -q -F "minimal_1"

portablectl detach --now --enable --runtime /tmp/minimal_1 minimal-app0

portablectl list | grep -q -F "No images."

root="/usr/share/minimal_0.raw"
app1="/usr/share/app1.raw"

portablectl attach --now --runtime --extension ${app1} ${root} app1

systemctl is-active app1.service
status="$(portablectl is-attached --extension ${app1} ${root})"
[[ "${status}" == "running-runtime" ]]
portablectl inspect --cat --extension ${app1} ${root} app1 | grep -q -F "${app1}"

portablectl reattach --now --runtime --extension ${app1} ${root} app1

systemctl is-active app1.service
status="$(portablectl is-attached --extension ${app1} ${root})"
[[ "${status}" == "running-runtime" ]]

portablectl detach --force --no-reload --runtime --extension ${app1} ${root} app1
portablectl attach --force --no-reload --runtime --extension ${app1} /usr/share/minimal_1.raw app1
systemctl daemon-reload
systemctl restart app1.service

systemctl is-active app1.service
status="$(portablectl is-attached --extension app1 minimal_0)"
[[ "${status}" == "running-runtime" ]]

portablectl detach --now --runtime --extension ${app1} /usr/share/minimal_1.raw app1

# Ensure that the combination of read-only images, state directory and dynamic user works, and that
# state is retained. Check after detaching, as on slow systems (eg: sanitizers) it might take a while
# after the service is attached before the file appears.
grep -q -F baz /var/lib/private/app1/foo

# portablectl also works with directory paths rather than images

mkdir /tmp/rootdir /tmp/app1 /tmp/overlay
mount ${app1} /tmp/app1
mount ${root} /tmp/rootdir
mount -t overlay overlay -o lowerdir=/tmp/app1:/tmp/rootdir /tmp/overlay

portablectl attach --copy=symlink --now --runtime /tmp/overlay app1

systemctl is-active app1.service

portablectl detach --now --runtime overlay app1

umount /tmp/overlay
umount /tmp/rootdir
umount /tmp/app1

mkdir -p /tmp/img/usr/lib/systemd/system
cp /usr/lib/os-release /tmp/img/usr/lib/
cat > /tmp/img/usr/lib/systemd/system/testservice-58.target <<EOF
[Unit]
Description=I am portable!
EOF

# The filesystem on the test image, despite being ext4, seems to have a mtime
# granularity of one second, which means the manager's unit cache won't be
# marked as dirty when writing the unit file, unless we wait at least a full
# second after the previous daemon-reload.
# May 07 23:12:20 systemd-testsuite testsuite-58.sh[30]: + cat
# May 07 23:12:20 systemd-testsuite testsuite-58.sh[30]: + ls -l --full-time /etc/systemd/system/testservice-48.service
# May 07 23:12:20 systemd-testsuite testsuite-58.sh[52]: -rw-r--r-- 1 root root 50 2020-05-07 23:12:20.000000000 +0100 /
# May 07 23:12:20 systemd-testsuite testsuite-58.sh[30]: + stat -f --format=%t /etc/systemd/system/testservice-48.servic
# May 07 23:12:20 systemd-testsuite testsuite-58.sh[53]: ef53
sleep 1.1

portablectl attach --copy=symlink --runtime --now --no-reload /tmp/img testservice-58

systemctl is-active testservice-58.target

portablectl detach --runtime --now --no-reload /tmp/img testservice-58
rm -rf /tmp/img

set +o pipefail
systemctl status testservice-58.target |& grep -q "Unit testservice-58.target could not be found"

echo OK > /testok

exit 0
