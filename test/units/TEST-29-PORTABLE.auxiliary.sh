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

have_fsverity=0
if command -v openssl >/dev/null 2>&1 && command -v fsverity >/dev/null 2>&1 && command -v xxd >/dev/null 2>&1; then
    # Unfortunately OpenSSL insists on reading some config file, hence provide one with mostly placeholder contents
    cat >/tmp/minimal_0.openssl.cnf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = DE
ST = Test State
L = Test Locality
O = Org Name
OU = Org Unit Name
CN = Common Name
emailAddress = test@email.com
EOF
    openssl req -config /tmp/minimal_0.openssl.cnf -new -x509 -newkey rsa:1024 -keyout /tmp/minimal_0.key -out /tmp/minimal_0.crt -days 365 -nodes
    openssl x509 -outform der -in /tmp/minimal_0.crt -out /tmp/minimal_0.cer

    # Given enabling verity is a one-way operation, and the host might need to mount the image (e.g.: to extract
    # logs) we create an ext4 filesystem that we use just for this test and then discard.
    dd if=/dev/zero of=/tmp/verity.ext4 bs=4M count=1
    # fsverity imposes that the filesystem's block size is equival to the kernel's page size. Default to 4KB.
    page_size="$(grep KernelPageSize /proc/self/smaps | head -n1 | awk '{print $2}')"
    if [ -z "${page_size}" ]; then
        page_size=4
    fi
    mkfs.ext4 -b "${page_size}k" -F /tmp/verity.ext4

    # Both mkfs and the kernel need to support verity, so don't fail if enabling or mounting fails
    if keyctl padd asymmetric "minimal_0" %keyring:.fs-verity < /tmp/minimal_0.cer && tune2fs -O verity /tmp/verity.ext4 && mount -o X-mount.mkdir /tmp/verity.ext4 /etc/systemd/system.attached/; then
        fsverity digest --hash-alg=sha256 --for-builtin-sig --compact /tmp/app0/usr/lib/systemd/system/app0.service | \
            tr -d '\n' | \
            xxd -p -r | \
                openssl smime -sign -nocerts -noattr -binary -in /dev/stdin -inkey /tmp/minimal_0.key -signer /tmp/minimal_0.crt -outform der -out /tmp/app0/usr/lib/systemd/system/app0.service.p7s

        have_fsverity=1
    fi
fi

mksquashfs /tmp/app0 /tmp/app0.raw -noappend
rm -rf /tmp/app0

portablectl "${ARGS[@]}" attach --now --extension /tmp/app0.raw /usr/share/minimal_0.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension app0 minimal_0)"
[[ "${status}" == "running" ]]

grep -q -F "LogExtraFields=PORTABLE_ROOT=minimal_0.raw" /etc/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0.raw" /etc/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /etc/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "org.freedesktop.app0" /etc/dbus-1/system.d/app0.conf
grep -q -F "org.freedesktop.app0" /etc/dbus-1/system-services/app0.service
grep -q -F "org.freedesktop.app0" /etc/polkit-1/actions/app0.policy
if [ "$have_fsverity" -eq 1 ]; then
    fsverity measure /etc/systemd/system.attached/app0.service
    fsverity measure /etc/systemd/system.attached/app0.service.d/20-portable.conf
    # Again, with signature enforcement, only the signed version should work
    echo 1 > /proc/sys/fs/verity/require_signatures
fi

portablectl "${ARGS[@]}" reattach --now --extension /tmp/app0.raw /usr/share/minimal_1.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension app0 minimal_1)"
[[ "${status}" == "running" ]]

grep -q -F "LogExtraFields=PORTABLE_ROOT=minimal_1.raw" /etc/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0.raw" /etc/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /etc/systemd/system.attached/app0.service.d/20-portable.conf
if [ "$have_fsverity" -eq 1 ]; then
    fsverity measure /etc/systemd/system.attached/app0.service
    fsverity measure /etc/systemd/system.attached/app0.service.d/20-portable.conf && { echo 'unexpected success'; exit 1; }
fi

portablectl detach --now --extension /tmp/app0.raw /usr/share/minimal_1.raw app0

test ! -f /etc/dbus-1/system.d/app0.conf
test ! -f /etc/dbus-1/system-services/app0.service
test ! -f /etc/polkit-1/actions/app0.policy
