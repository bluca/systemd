/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "bitfield.h"
#include "bus-polkit.h"
#include "cgroup.h"
#include "condition.h"
#include "execute.h"
#include "format-util.h"
#include "install.h"
#include "json-util.h"
#include "manager.h"
#include "path-util.h"
#include "pidref.h"
#include "selinux-access.h"
#include "service.h"
#include "set.h"
#include "special.h"
#include "strv.h"
#include "unit.h"
#include "varlink-cgroup.h"
#include "varlink-common.h"
#include "varlink-execute.h"
#include "varlink-unit.h"
#include "varlink-util.h"

#define JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY(name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(value > EMERGENCY_ACTION_NONE, name, SD_JSON_BUILD_STRING(emergency_action_to_string(value)))

static int unit_dependencies_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        UnitDependency d;
        int r;

        assert(ret);
        assert(name);

        d = unit_dependency_from_string(name);
        if (d < 0)
                return log_debug_errno(d, "Failed to get unit dependency for '%s': %m", name);

        void *value;
        Unit *other;
        HASHMAP_FOREACH_KEY(value, other, unit_get_dependencies(u, d)) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(other->id));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_mounts_for_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Hashmap **mounts_for = userdata;
        UnitMountDependencyType d;
        const char *p;
        void *value;
        int r;

        assert(ret);
        assert(name);

        if (!mounts_for) {
                *ret = NULL;
                return 0;
        }

        d = unit_mount_dependency_type_from_string(name);
        if (d < 0)
                return log_debug_errno(d, "Failed to get unit mount dependency for '%s': %m", name);

        HASHMAP_FOREACH_KEY(value, p, mounts_for[d]) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(p));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_conditions_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        bool do_asserts = streq(name, "Asserts");
        Condition *list = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(conditions, c, list) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("type", do_asserts ? assert_type_to_string(c->type)
                                                                             : condition_type_to_string(c->type)),
                                SD_JSON_BUILD_PAIR_BOOLEAN("trigger", c->trigger),
                                SD_JSON_BUILD_PAIR_BOOLEAN("negate", c->negate),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("parameter", c->parameter));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);

        /* The main principle behind context/runtime split is the following:
         * If it make sense to place a property into a config/unit file it belongs to Context.
         * Otherwise it's a 'Runtime'. */

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("Type", unit_type_to_string(u->type)),
                        SD_JSON_BUILD_PAIR_STRING("ID", u->id),
                        SD_JSON_BUILD_PAIR_CONDITION(!set_isempty(u->aliases), "Names", JSON_BUILD_STRING_SET(u->aliases)),

                        /* [Unit] Section Options
                         * https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#%5BUnit%5D%20Section%20Options */
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Description", u->description),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Documentation", u->documentation),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Wants", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("WantedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Requires", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequiredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Requisite", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequisiteOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BindsTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BoundBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PartOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConsistsOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Upholds", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("UpheldBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Conflicts", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConflictedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Before", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("After", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnFailure", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnFailureOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnSuccess", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnSuccessOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PropagatesReloadTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ReloadPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PropagatesStopTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StopPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("JoinsNamespaceOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequiresMountsFor", unit_mounts_for_build_json, &u->mounts_for),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("WantsMountsFor", unit_mounts_for_build_json, &u->mounts_for),
                        SD_JSON_BUILD_PAIR_STRING("OnSuccessJobMode", job_mode_to_string(u->on_success_job_mode)),
                        SD_JSON_BUILD_PAIR_STRING("OnFailureJobMode", job_mode_to_string(u->on_failure_job_mode)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("IgnoreOnIsolate", u->ignore_on_isolate),
                        SD_JSON_BUILD_PAIR_BOOLEAN("StopWhenUnneeded", u->stop_when_unneeded),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RefuseManualStart", u->refuse_manual_start),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RefuseManualStop", u->refuse_manual_stop),
                        SD_JSON_BUILD_PAIR_BOOLEAN("AllowIsolate", u->allow_isolate),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultDependencies", u->default_dependencies),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SurviveFinalKillSignal", u->survive_final_kill_signal),
                        SD_JSON_BUILD_PAIR_STRING("CollectMode", collect_mode_to_string(u->collect_mode)),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("FailureAction", u->failure_action),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("SuccessAction", u->success_action),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("FailureActionExitStatus", u->failure_action_exit_status),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("SuccessActionExitStatus", u->success_action_exit_status),
                        JSON_BUILD_PAIR_FINITE_USEC("JobTimeoutUSec", u->job_timeout),
                        JSON_BUILD_PAIR_FINITE_USEC("JobRunningTimeoutUSec", u->job_running_timeout),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("JobTimeoutAction", u->job_timeout_action),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("JobTimeoutRebootArgument", u->job_timeout_reboot_arg),
                        JSON_BUILD_PAIR_RATELIMIT_ENABLED("StartLimit", &u->start_ratelimit),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("StartLimitAction", u->start_limit_action),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RebootArgument", u->reboot_arg),

                        /* Conditions and Asserts
                         * https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Conditions%20and%20Asserts */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Conditions", unit_conditions_build_json, u->conditions),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Asserts", unit_conditions_build_json, u->asserts),

                        /* Others */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Triggers", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TriggeredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("AccessSELinuxContext", u->access_selinux_context),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("FragmentPath", u->fragment_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SourcePath", u->source_path),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("DropInPaths", u->dropin_paths),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UnitFilePreset", preset_action_past_tense_to_string(unit_get_unit_file_preset(u))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Transient", u->transient),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Perpetual", u->perpetual),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DebugInvocation", u->debug_invocation),

                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CGroup", unit_cgroup_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Exec", unit_exec_context_build_json, u));

        // TODO follow up PRs:
        // JSON_BUILD_PAIR_CALLBACK_NON_NULL("Exec", exec_context_build_json, u)
        // JSON_BUILD_PAIR_CALLBACK_NON_NULL("Kill", kill_context_build_json, u)
        // Mount/Automount context
        // Path context
        // Scope context
        // Swap context
        // Timer context
        // Service context
        // Socket context
}

static int can_clean_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        ExecCleanMask mask;
        int r;

        assert(ret);

        r = unit_can_clean(u, &mask);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if unit can be cleaned: %m");

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                if (!BIT_SET(mask, t))
                        continue;

                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(exec_resource_type_to_string(t)));
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(mask, EXEC_CLEAN_FDSTORE)) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING("fdstore"));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int markers_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        unsigned *markers = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        BIT_FOREACH(m, *markers) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(unit_marker_to_string(m)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int activation_details_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const ActivationDetails *activation_details = userdata;
        _cleanup_strv_free_ char **pairs = NULL;
        int r;

        assert(ret);

        /* activation_details_append_pair() gracefully takes activation_details==NULL */
        r = activation_details_append_pair(activation_details, &pairs);
        if (r < 0)
                return log_debug_errno(r, "Failed to get activation details: %m");

        STRV_FOREACH_PAIR(key, value, pairs) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("type", *key),
                                SD_JSON_BUILD_PAIR_STRING("name", *value));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        Unit *f = unit_following(u);

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Following", f ? f->id : NULL),
                        SD_JSON_BUILD_PAIR_STRING("LoadState", unit_load_state_to_string(u->load_state)),
                        SD_JSON_BUILD_PAIR_STRING("ActiveState", unit_active_state_to_string(unit_active_state(u))),
                        SD_JSON_BUILD_PAIR_STRING("FreezerState", freezer_state_to_string(u->freezer_state)),
                        SD_JSON_BUILD_PAIR_STRING("SubState", unit_sub_state_to_string(u)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UnitFileState", unit_file_state_to_string(unit_get_unit_file_state(u))),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("StateChangeTimestamp", &u->state_change_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("ActiveEnterTimestamp", &u->active_enter_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("ActiveExitTimestamp", &u->active_exit_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InactiveEnterTimestamp", &u->inactive_enter_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InactiveExitTimestamp", &u->inactive_exit_timestamp),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanStart", unit_can_start_refuse_manual(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanStop", unit_can_stop_refuse_manual(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanReload", unit_can_reload(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanIsolate", unit_can_isolate_refuse_manual(u)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CanClean", can_clean_build_json, u),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanFreeze", unit_can_freeze(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanLiveMount", unit_can_live_mount(u, /* error= */ NULL) >= 0),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("JobId", u->job ? u->job->id : 0),
                        SD_JSON_BUILD_PAIR_BOOLEAN("NeedDaemonReload", unit_need_daemon_reload(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ConditionResult", u->condition_result),
                        SD_JSON_BUILD_PAIR_BOOLEAN("AssertResult", u->assert_result),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("ConditionTimestamp", &u->condition_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("AssertTimestamp", &u->assert_timestamp),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(u->invocation_id), "InvocationID", SD_JSON_BUILD_UUID(u->invocation_id)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Markers", markers_build_json, &u->markers),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ActivationDetails", activation_details_build_json, u->activation_details),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CGroup", unit_cgroup_runtime_build_json, u));
}

static int list_unit_one(sd_varlink *link, Unit *unit, bool more) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(unit);

        r = sd_json_buildo(
                &v,
                SD_JSON_BUILD_PAIR_CALLBACK("context", unit_context_build_json, unit),
                SD_JSON_BUILD_PAIR_CALLBACK("runtime", unit_runtime_build_json, unit));
        if (r < 0)
                return r;

        if (more)
                return sd_varlink_notify(link, v);

        return sd_varlink_reply(link, v);
}

static int list_unit_one_with_selinux_access_check(sd_varlink *link, Unit *unit, bool more) {
        int r;

        assert(link);
        assert(unit);

        r = mac_selinux_unit_access_check_varlink(unit, link, "status");
        if (r < 0)
                /* If mac_selinux_unit_access_check_varlink() returned a error,
                 * it means that SELinux enforce is on. It also does all the logging(). */
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        return list_unit_one(link, unit, more);
}

static int lookup_unit_by_pidref(sd_varlink *link, Manager *manager, PidRef *pidref, Unit **ret_unit) {
        _cleanup_(pidref_done) PidRef peer = PIDREF_NULL;
        Unit *unit;
        int r;

        assert(link);
        assert(manager);
        assert(ret_unit);

        if (pidref_is_automatic(pidref)) {
                r = varlink_get_peer_pidref(link, &peer);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get peer pidref: %m");

                pidref = &peer;
        } else if (!pidref_is_set(pidref))
                return -EINVAL;

        unit = manager_get_unit_by_pidref(manager, pidref);
        if (!unit)
                return -ESRCH;

        *ret_unit = unit;
        return 0;
}

typedef struct UnitLookupParameters {
        const char *name, *cgroup, *mode;
        PidRef pidref;
        sd_id128_t invocation_id;
} UnitLookupParameters;

static void unit_lookup_parameters_done(UnitLookupParameters *p) {
        assert(p);
        pidref_done(&p->pidref);
}

static int varlink_error_no_such_unit(sd_varlink *v, const char *name) {
        return sd_varlink_errorbo(
                        ASSERT_PTR(v),
                        VARLINK_ERROR_UNIT_NO_SUCH_UNIT,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("parameter", name));
}

static int varlink_error_only_by_dependency(sd_varlink *v, const char *name) {
        return sd_varlink_errorbo(
                        ASSERT_PTR(v),
                        VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("parameter", name));
}

static int varlink_error_bus_shutting_down(sd_varlink *v, const char *name) {
        return sd_varlink_errorbo(
                        ASSERT_PTR(v),
                        VARLINK_ERROR_UNIT_BUS_SHUTTING_DOWN,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("parameter", name));
}

static int varlink_error_conflict_lookup_parameters(sd_varlink *v, const UnitLookupParameters *p) {
        log_debug_errno(
                        ESRCH,
                        "Searching unit by lookup parameters name='%s' pid="PID_FMT" cgroup='%s' invocationID='%s' resulted in multiple different units",
                        p->name,
                        p->pidref.pid,
                        p->cgroup,
                        sd_id128_is_null(p->invocation_id) ? "" : SD_ID128_TO_UUID_STRING(p->invocation_id));

        return varlink_error_no_such_unit(v, /* name= */ NULL);
}

static int lookup_unit_by_parameters(sd_varlink *link, Manager *manager, UnitLookupParameters *p, Unit **ret_unit) {
        /* The function can return ret_unit=NULL if no lookup parameters provided */
        Unit *unit = NULL;
        int r;

        assert(link);
        assert(manager);
        assert(p);
        assert(ret_unit);

        if (p->name) {
                unit = manager_get_unit(manager, p->name);
                if (!unit)
                        return varlink_error_no_such_unit(link, "name");
        }

        if (pidref_is_set_or_automatic(&p->pidref)) {
                Unit *pid_unit;
                r = lookup_unit_by_pidref(link, manager, &p->pidref, &pid_unit);
                if (r == -EINVAL)
                        return sd_varlink_error_invalid_parameter_name(link, "pid");
                if (r == -ESRCH)
                        return varlink_error_no_such_unit(link, "pid");
                if (r < 0)
                        return r;
                if (pid_unit != unit && unit != NULL)
                        return varlink_error_conflict_lookup_parameters(link, p);

                unit = pid_unit;
        }

        if (p->cgroup) {
                if (!path_is_safe(p->cgroup))
                        return sd_varlink_error_invalid_parameter_name(link, "cgroup");

                Unit *cgroup_unit = manager_get_unit_by_cgroup(manager, p->cgroup);
                if (!cgroup_unit)
                        return varlink_error_no_such_unit(link, "cgroup");
                if (cgroup_unit != unit && unit != NULL)
                        return varlink_error_conflict_lookup_parameters(link, p);

                unit = cgroup_unit;
        }

        if (!sd_id128_is_null(p->invocation_id)) {
                Unit *id128_unit = hashmap_get(manager->units_by_invocation_id, &p->invocation_id);
                if (!id128_unit)
                        return varlink_error_no_such_unit(link, "invocationID");
                if (id128_unit != unit && unit != NULL)
                        return varlink_error_conflict_lookup_parameters(link, p);

                unit = id128_unit;
        }

        *ret_unit = unit;
        return 0;
}

int vl_method_list_units(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",         SD_JSON_VARIANT_STRING,        json_dispatch_const_unit_name, offsetof(UnitLookupParameters, name),          0 /* allows UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE */ },
                { "pid",          _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref,          offsetof(UnitLookupParameters, pidref),        SD_JSON_RELAX /* allows PID_AUTOMATIC */            },
                { "cgroup",       SD_JSON_VARIANT_STRING,        json_dispatch_const_path,      offsetof(UnitLookupParameters, cgroup),        SD_JSON_STRICT /* require normalized path */        },
                { "invocationID", SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,        offsetof(UnitLookupParameters, invocation_id), 0                                                   },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
         _cleanup_(unit_lookup_parameters_done) UnitLookupParameters p = {
                 .pidref = PIDREF_NULL,
        };
        Unit *unit, *previous = NULL;
        const char *k;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = lookup_unit_by_parameters(link, manager, &p, &unit);
        if (r < 0)
                return r;
        if (unit)
                return list_unit_one_with_selinux_access_check(link, unit, /* more = */ false);

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        HASHMAP_FOREACH_KEY(unit, k, manager->units) {
                /* ignore aliases */
                if (k != unit->id)
                        continue;

                if (previous) {
                        r = list_unit_one(link, previous, /* more = */ true);
                        if (r < 0)
                                return r;
                }

                previous = unit;
        }

        if (previous)
                return list_unit_one(link, previous, /* more = */ false);

        return sd_varlink_error(link, "io.systemd.Manager.NoSuchUnit", NULL);
}

static int varlink_unit_queue_job_one(
                sd_varlink *link,
                Unit *u,
                JobType type,
                JobMode mode,
                bool reload_if_possible) {

        _cleanup_free_ char *job_path = NULL, *unit_path = NULL;
        Job *j;
        int r;

        if (reload_if_possible && unit_can_reload(u)) {
                if (type == JOB_RESTART)
                        type = JOB_RELOAD_OR_START;
                else if (type == JOB_TRY_RESTART)
                        type = JOB_TRY_RELOAD;
        }

        if (type == JOB_STOP && UNIT_IS_LOAD_ERROR(u->load_state) && unit_active_state(u) == UNIT_INACTIVE)
                return varlink_error_no_such_unit(link, "name");

        if ((type == JOB_START && u->refuse_manual_start) ||
            (type == JOB_STOP && u->refuse_manual_stop) ||
            (IN_SET(type, JOB_RESTART, JOB_TRY_RESTART) && (u->refuse_manual_start || u->refuse_manual_stop)) ||
            (type == JOB_RELOAD_OR_START && job_type_collapse(type, u) == JOB_START && u->refuse_manual_start))
                return varlink_error_only_by_dependency(link, "name");

        /* dbus-broker issues StartUnit for activation requests, and Type=dbus services automatically
         * gain dependency on dbus.socket. Therefore, if dbus has a pending stop job, the new start
         * job that pulls in dbus again would cause job type conflict. Let's avoid that by rejecting
         * job enqueuing early.
         *
         * Note that unlike signal_activation_request(), we can't use unit_inactive_or_pending()
         * here. StartUnit is a more generic interface, and thus users are allowed to use e.g. systemctl
         * to start Type=dbus services even when dbus is inactive. */
        if (type == JOB_START && u->type == UNIT_SERVICE && SERVICE(u)->type == SERVICE_DBUS)
                FOREACH_STRING(dbus_unit, SPECIAL_DBUS_SOCKET, SPECIAL_DBUS_SERVICE) {
                        Unit *dbus;

                        dbus = manager_get_unit(u->manager, dbus_unit);
                        if (dbus && unit_stop_pending(dbus))
                                return varlink_error_bus_shutting_down(link, "name");
                }

        r = manager_add_job(u->manager, type, u, mode, /* error= */ NULL, &j);
        if (r < 0)
                return r;

        // r = bus_job_track_sender(j, message);
        // if (r < 0)
        //         return r;

        // /* Before we send the method reply, force out the announcement JobNew for this job */
        // bus_job_send_pending_change_signal(j, true);

        // job_path = job_dbus_path(j);
        // if (!job_path)
        //         return -ENOMEM;

        // return sd_bus_message_append(reply, "o", job_path);
        return 0;
}

static int varlink_verify_manage_units_async(
                sd_varlink *link,
                Manager *manager,
                const char *id,
                const char *verb,
                const char *polkit_message) {

        const char *details[9];
        size_t n_details = 0;

        assert(manager);
        assert(link);

        if (id) {
                details[n_details++] = "unit";
                details[n_details++] = id;
        }

        if (verb) {
                details[n_details++] = "verb";
                details[n_details++] = verb;
        };

        if (polkit_message) {
                details[n_details++] = "polkit.message";
                details[n_details++] = polkit_message;
                details[n_details++] = "polkit.gettext_domain";
                details[n_details++] = GETTEXT_PACKAGE;
        }

        assert(n_details < ELEMENTSOF(details));
        details[n_details] = NULL;

        return varlink_verify_polkit_async(
                        link,
                        manager->system_bus,
                        "org.freedesktop.systemd1.manage-units",
                        n_details > 0 ? details : NULL,
                        &manager->polkit_registry);
}

static int method_manage_unit(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata,
                JobType job_type,
                bool reload_if_possible) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, offsetof(UnitLookupParameters, name), 0 /* allows UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE */ },
                { "mode", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(UnitLookupParameters, mode), 0 },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
         _cleanup_(unit_lookup_parameters_done) UnitLookupParameters p = {
                 .pidref = PIDREF_NULL,
        };
        const char *verb;
        JobMode mode;
        Unit *unit;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = lookup_unit_by_parameters(link, manager, &p, &unit);
        if (r < 0)
                return r;

        if (reload_if_possible)
                verb = strjoina("reload-or-", job_type_to_string(job_type));
        else
                verb = job_type_to_string(job_type);

        mode = job_mode_from_string(p.mode);
        if (mode < 0)
                return sd_varlink_error_invalid_parameter_name(link, "mode");

        r = mac_selinux_unit_access_check_varlink(unit, link, job_type_to_access_method(job_type));
        if (r < 0)
                return r;

        r = varlink_verify_manage_units_async(
                        link,
                        manager,
                        unit->id,
                        verb,
                        polkit_message_for_job[job_type]);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        return varlink_unit_queue_job_one(link, unit, job_type, mode, reload_if_possible);
}

int vl_method_reload_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return method_manage_unit(link, parameters, flags, userdata, JOB_RELOAD, /* reload_if_possible= */ false);
}

int vl_method_start_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return method_manage_unit(link, parameters, flags, userdata, JOB_START, /* reload_if_possible= */ false);
}

int vl_method_stop_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return method_manage_unit(link, parameters, flags, userdata, JOB_STOP, /* reload_if_possible= */ false);
}

int vl_method_restart_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return method_manage_unit(link, parameters, flags, userdata, JOB_RESTART, /* reload_if_possible= */ false);
}

int vl_method_try_restart_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return method_manage_unit(link, parameters, flags, userdata, JOB_TRY_RESTART, /* reload_if_possible= */ false);
}

int vl_method_reload_or_restart_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return method_manage_unit(link, parameters, flags, userdata, JOB_RELOAD_OR_START, /* reload_if_possible= */ true);
}

int vl_method_reload_or_try_restart_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return method_manage_unit(link, parameters, flags, userdata, JOB_TRY_RESTART, /* reload_if_possible= */ true);
}
