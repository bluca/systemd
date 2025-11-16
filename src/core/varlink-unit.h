/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

#define VARLINK_ERROR_UNIT_NO_SUCH_UNIT "io.systemd.Unit.NoSuchUnit"
#define VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY "io.systemd.Unit.OnlyByDependency"
#define VARLINK_ERROR_UNIT_BUS_SHUTTING_DOWN "io.systemd.Unit.BusShuttingDown"

int vl_method_list_units(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_reload_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_start_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_stop_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_restart_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_try_restart_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_reload_or_restart_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_reload_or_try_restart_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
