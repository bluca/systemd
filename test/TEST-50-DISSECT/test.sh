#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="test systemd-dissect"
IMAGE_NAME="dissect"
TEST_NO_NSPAWN=1
TEST_INSTALL_VERITY_MINIMAL=1

. $TEST_BASE_DIR/test-functions

command -v mksquashfs >/dev/null 2>&1 || exit 0
command -v veritysetup >/dev/null 2>&1 || exit 0
command -v sfdisk >/dev/null 2>&1 || exit 0

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/testsuite.sh
Type=oneshot
EOF
        cp testsuite.sh $initdir/

        setup_testsuite

        # Need loop devices for systemd-dissect
        instmods loop =block
        instmods squashfs =squashfs
        instmods dm_verity =md
        instmods overlay =overlayfs
        install_dmevent
        generate_module_dependencies
        inst_binary mktemp
        inst_binary sfdisk
        inst_binary losetup
        inst_binary uname
        inst_binary cut
        inst_binary dd
    )
    setup_nspawn_root
}

do_test "$@"
