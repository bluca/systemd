#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

root="/usr/share/minimal.raw"
app0="/usr/share/app0.raw"

portablectl attach --now --runtime --extra-image ${app0} ${root} app0

systemctl is-active app0.service

portablectl detach --now --runtime app0

echo OK > /testok

exit 0
