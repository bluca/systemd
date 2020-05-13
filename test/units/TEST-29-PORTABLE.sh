#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

install_extension_images

# Set longer timeout for slower machines, e.g. non-KVM vm.
mkdir -p /run/systemd/system.conf.d
cat >/run/systemd/system.conf.d/10-timeout.conf <<EOF
[Manager]
DefaultEnvironment=SYSTEMD_DISSECT_VERITY_TIMEOUT_SEC=30
ManagerEnvironment=SYSTEMD_DISSECT_VERITY_TIMEOUT_SEC=30
EOF

mkdir -p /run/systemd/system/systemd-portabled.service.d/
cat <<EOF >/run/systemd/system/systemd-portabled.service.d/override.conf
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF

systemctl daemon-reexec


udevadm control --log-level debug

ARGS=()
STATE_DIRECTORY=/var/lib/private/
if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
    # If we're running under sanitizers, we need to use a less restrictive
    # profile, otherwise LSan syscall would get blocked by seccomp
    ARGS+=(--profile=trusted)
    # With the trusted profile DynamicUser is disabled, so the storage is not in private/
    STATE_DIRECTORY=/var/lib/
fi
export STATE_DIRECTORY
export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_DISSECT_VERITY_TIMEOUT_SEC=30

# Quick smoke tests

systemd-dissect --no-pager /usr/share/minimal_0.raw | grep -q '✓ portable service'
systemd-dissect --no-pager /usr/share/minimal_1.raw | grep -q '✓ portable service'
systemd-dissect --no-pager /tmp/app0.raw | grep -q '✓ sysext for portable service'
systemd-dissect --no-pager /tmp/app1.raw | grep -q '✓ sysext for portable service'
systemd-dissect --no-pager /tmp/conf0.raw | grep -q '✓ confext for portable service'

# Lack of ID field in os-release should be rejected, but it caused a crash in the past instead
mkdir -p /tmp/emptyroot/usr/lib
mkdir -p /tmp/emptyext/usr/lib/extension-release.d
touch /tmp/emptyroot/usr/lib/os-release
touch /tmp/emptyext/usr/lib/extension-release.d/extension-release.emptyext

# Remote peer disconnected -> portabled crashed
res="$(! portablectl attach --extension /tmp/emptyext /tmp/emptyroot 2> >(grep "Remote peer disconnected"))"
test -z "${res}"

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

: "Run subtests"

run_subtests

touch /testok
