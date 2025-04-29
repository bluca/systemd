/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Dissect.h"

static SD_VARLINK_DEFINE_METHOD(
                Attach,
                // VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The absolute path to the source DDI to attach"),
                SD_VARLINK_DEFINE_INPUT(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("File descriptor of attached DDI"),
                SD_VARLINK_DEFINE_OUTPUT(fileDescriptor, SD_VARLINK_INT, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Dissect,
                "io.systemd.Dissect",
                SD_VARLINK_INTERFACE_COMMENT("Attach DDI"),
                &vl_method_Attach);
