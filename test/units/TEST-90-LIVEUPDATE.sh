#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug

# This test verifies that the Live Update Orchestrator (LUO) integration works:
# - PID 1 can serialize fd stores and pass them to systemd-shutdown
# - systemd-shutdown can preserve fds in a LUO session before kexec
# - After kexec, PID 1 restores the fd stores from the LUO session
#
# The test requires KHO (Kexec HandOver) and LUO (Live Update Orchestrator) kernel support.

if [[ ! -e /dev/liveupdate ]]; then
    echo "/dev/liveupdate not available, skipping test"
    exit 0
fi

# Ensure kexec tools are available
if ! command -v kexec >/dev/null 2>&1; then
    echo "kexec not available, skipping test"
    exit 0
fi

# To test the late-load path also create a unit that appears at runtime
# ExecStart is added later depending on the test phase
cat >/run/systemd/system/TEST-90-LIVEUPDATE-late.service <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
FileDescriptorStoreMax=20
FileDescriptorStorePreserve=yes
EOF

if ! grep -q systemd.test.luo_second_boot=1 /proc/cmdline; then
    # Create memfds with known content and push them to our fd store.
    # Also request a LUO session, store a memfd in it, and push the session fd to the fd store.
    /usr/lib/systemd/tests/unit-tests/manual/test-luo store

    # Complete and start the late unit — use a different session name prefix to avoid collisions
    cat >>/run/systemd/system/TEST-90-LIVEUPDATE-late.service <<EOF
ExecStart=/usr/lib/systemd/tests/unit-tests/manual/test-luo store late
EOF
    systemctl start TEST-90-LIVEUPDATE-late.service

    # Verify the late unit has fds in its store
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-90-LIVEUPDATE-late.service)
    echo "Late unit fd store count after store: $n_fds"
    test "$n_fds" -ge 1

    # Extract kernel and initrd from the booted UKI
    CURRENT_UKI=$(bootctl --print-stub-path)
    if [[ -z "$CURRENT_UKI" ]]; then
        echo "Cannot determine booted UKI path, skipping test"
        exit 0
    fi

    echo "Booted UKI: $CURRENT_UKI"

    KERNEL=/tmp/luo-test-vmlinuz
    INITRD=/tmp/luo-test-initrd

    objcopy -O binary --only-section=.linux "$CURRENT_UKI" "$KERNEL"
    objcopy -O binary --only-section=.initrd "$CURRENT_UKI" "$INITRD"

    # Verify we got something
    if [[ ! -s "$KERNEL" ]]; then
        echo "Failed to extract kernel from UKI, skipping test"
        rm -f "$KERNEL" "$INITRD"
        exit 0
    fi

    echo "Using kernel: $KERNEL"
    echo "Using initrd: $INITRD"

    # Read the current kernel command line, add our marker for second boot detection
    CMDLINE="$(</proc/cmdline) systemd.test.luo_second_boot=1"

    # Load the kexec kernel (using -s for in-kernel kexec file loader, needed for KHO)
    echo "Loading kexec kernel..."
    kexec -l "$KERNEL" -s --initrd="$INITRD" --command-line="$CMDLINE"

    rm -f "$KERNEL" "$INITRD"

    systemctl kexec
    exit 0
else
    # Verify that the fd store survived the kexec (memfds + LUO session).
    /usr/lib/systemd/tests/unit-tests/manual/test-luo check

    # Complete and start the late unit
    cat >>/run/systemd/system/TEST-90-LIVEUPDATE-late.service <<EOF
ExecStart=/usr/lib/systemd/tests/unit-tests/manual/test-luo check late
EOF
    systemctl start TEST-90-LIVEUPDATE-late.service
fi

touch /testok
systemctl --no-block exit 123
