#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="test systemd-portabled"
TEST_INSTALL_VERITY_MINIMAL=1
TEST_NO_NSPAWN=1
IMAGE_NAME="dissect"

command -v mksquashfs >/dev/null 2>&1 || exit 0
command -v veritysetup >/dev/null 2>&1 || exit 0

. $TEST_BASE_DIR/test-functions

# Need loop devices for systemd-portabled
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

        instmods loop =block
        instmods squashfs =squashfs
        instmods dm_verity =md
        instmods overlay =overlayfs
        install_dmevent
        generate_module_dependencies
        inst_binary losetup
    )
    setup_nspawn_root
}

do_test "$@"
