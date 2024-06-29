#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
# shellcheck disable=SC2233,SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Arrays cannot be exported, so redefine in each test script
ARGS=()
if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
    # If we're running under sanitizers, we need to use a less restrictive
    # profile, otherwise LSan syscall would get blocked by seccomp
    ARGS+=(--profile=trusted)
fi

mkdir -p /tmp/rootdir \
    /tmp/app0 \
    /tmp/app1 \
    /tmp/overlay \
    /tmp/os-release-fix \
    /tmp/os-release-fix/etc \
    /tmp/os-release-fix/usr/share/dbus-1/system.d/ \
    /tmp/os-release-fix/usr/share/dbus-1/system-services/ \
    /tmp/os-release-fix/usr/share/polkit-1/actions/
mount /tmp/app0.raw /tmp/app0
mount /tmp/app1.raw /tmp/app1
mount /usr/share/minimal_0.raw /tmp/rootdir

cat <<EOF >/tmp/os-release-fix/usr/share/dbus-1/system.d/app1.conf
<?xml version="1.0"?> <!--*-nxml-*-->
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
        "https://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
        <policy user="root">
                <allow own="org.freedesktop.app1"/>
                <allow send_destination="org.freedesktop.app1"/>
                <allow receive_sender="org.freedesktop.app1"/>
        </policy>
        <policy context="default">
                <allow send_destination="org.freedesktop.app1"/>
                <allow receive_sender="org.freedesktop.app1"/>
        </policy>
</busconfig>
EOF
cat <<EOF >/tmp/os-release-fix/usr/share/dbus-1/system-services/app1.service
[D-BUS Service]
Name=org.freedesktop.app1
Exec=/bin/false
User=root
SystemdService=dbus-org.freedesktop.app1.service
EOF
cat <<EOF >/tmp/os-release-fix/usr/share/polkit-1/actions/app1.policy
<?xml version="1.0" encoding="UTF-8"?> <!--*-nxml-*-->
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
        "https://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
        <vendor>The systemd Project</vendor>
        <vendor_url>https://systemd.io</vendor_url>

        <action id="org.freedesktop.app1">
                <description gettext-domain="systemd">app1</description>
                <message gettext-domain="systemd">Authentication is required for app1</message>
                <defaults>
                        <allow_any>auth_admin</allow_any>
                        <allow_inactive>auth_admin</allow_inactive>
                        <allow_active>auth_admin_keep</allow_active>
                </defaults>
        </action>
</policyconfig>
EOF

# Fix up os-release to drop the valid PORTABLE_SERVICES field (because we are
# bypassing the sysext logic in portabled here it will otherwise not see the
# extensions additional valid prefix)
grep -v "^PORTABLE_PREFIXES=" /tmp/rootdir/etc/os-release >/tmp/os-release-fix/etc/os-release

mount -t overlay overlay -o lowerdir=/tmp/os-release-fix:/tmp/app1:/tmp/rootdir /tmp/overlay

grep . /tmp/overlay/usr/lib/extension-release.d/*
grep . /tmp/overlay/etc/os-release

portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/overlay app1

systemctl is-active app1.service

grep -q -F "org.freedesktop.app1" /etc/dbus-1/system.d/app1.conf
grep -q -F "org.freedesktop.app1" /etc/dbus-1/system-services/app1.service
grep -q -F "org.freedesktop.app1" /etc/polkit-1/actions/app1.policy

portablectl detach --now --runtime overlay app1

test ! -f /etc/dbus-1/system.d/app1.conf
test ! -f /etc/dbus-1/system-services/app1.service
test ! -f /etc/polkit-1/actions/app1.policy

# Ensure --force works also when symlinking
mkdir -p /run/systemd/system.attached/app1.service.d
cat <<EOF >/run/systemd/system.attached/app1.service
[Unit]
Description=App 1
EOF
cat <<EOF >/run/systemd/system.attached/app1.service.d/10-profile.conf
[Unit]
Description=App 1
EOF
cat <<EOF >/run/systemd/system.attached/app1.service.d/20-portable.conf
[Unit]
Description=App 1
EOF
systemctl daemon-reload

portablectl "${ARGS[@]}" attach --force --copy=symlink --now --runtime /tmp/overlay app1

systemctl is-active app1.service

portablectl detach --now --runtime overlay app1

umount /tmp/overlay
umount /tmp/app0
umount /tmp/app1
umount /tmp/rootdir
rm -rf /tmp/rootdir \
    /tmp/app0 \
    /tmp/app1 \
    /tmp/overlay \
    /tmp/os-release-fix

rm -rf /tmp/app0
unsquashfs -dest /tmp/app0 /tmp/app0.raw
mkdir -p /tmp/app0/usr/share/dbus-1/system.d/ \
    /tmp/app0/usr/share/dbus-1/system-services/ \
    /tmp/app0/usr/share/polkit-1/actions/
cat <<EOF >/tmp/app0/usr/share/dbus-1/system.d/app0.conf
<?xml version="1.0"?> <!--*-nxml-*-->
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
        "https://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
        <policy user="root">
                <allow own="org.freedesktop.app0"/>
                <allow send_destination="org.freedesktop.app0"/>
                <allow receive_sender="org.freedesktop.app0"/>
        </policy>
        <policy context="default">
                <allow send_destination="org.freedesktop.app0"/>
                <allow receive_sender="org.freedesktop.app0"/>
        </policy>
</busconfig>
EOF
cat <<EOF >/tmp/app0/usr/share/dbus-1/system-services/app0.service
[D-BUS Service]
Name=org.freedesktop.app0
Exec=/bin/false
User=root
SystemdService=dbus-org.freedesktop.app0.service
EOF
cat <<EOF >/tmp/app0/usr/share/polkit-1/actions/app0.policy
<?xml version="1.0" encoding="UTF-8"?> <!--*-nxml-*-->
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
        "https://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
        <vendor>The systemd Project</vendor>
        <vendor_url>https://systemd.io</vendor_url>

        <action id="org.freedesktop.app0">
                <description gettext-domain="systemd">app0</description>
                <message gettext-domain="systemd">Authentication is required for app0</message>
                <defaults>
                        <allow_any>auth_admin</allow_any>
                        <allow_inactive>auth_admin</allow_inactive>
                        <allow_active>auth_admin_keep</allow_active>
                </defaults>
        </action>
</policyconfig>
EOF
mksquashfs /tmp/app0 /tmp/app0.raw -noappend
rm -rf /tmp/app0

portablectl "${ARGS[@]}" attach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension app0 minimal_0)"
[[ "${status}" == "running-runtime" ]]

grep -q -F "LogExtraFields=PORTABLE_ROOT=minimal_0.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "org.freedesktop.app0" /etc/dbus-1/system.d/app0.conf
grep -q -F "org.freedesktop.app0" /etc/dbus-1/system-services/app0.service
grep -q -F "org.freedesktop.app0" /etc/polkit-1/actions/app0.policy

portablectl "${ARGS[@]}" reattach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_1.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension app0 minimal_1)"
[[ "${status}" == "running-runtime" ]]

grep -q -F "LogExtraFields=PORTABLE_ROOT=minimal_1.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /run/systemd/system.attached/app0.service.d/20-portable.conf

portablectl detach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_1.raw app0

test ! -f /etc/dbus-1/system.d/app0.conf
test ! -f /etc/dbus-1/system-services/app0.service
test ! -f /etc/polkit-1/actions/app0.policy
