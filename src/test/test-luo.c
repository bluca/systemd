/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Helper for TEST-90-LIVEUPDATE: creates memfds and stores them in the fd store,
 * requests a LUO session and stores a memfd in it, or verifies everything after kexec.
 *
 * Usage:
 *   test-luo store - create memfds and a LUO session, push all to the fd store
 *   test-luo check - verify fd store content and LUO session memfd after kexec
 */

#include <fcntl.h>
#include <linux/liveupdate.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "luo-util.h"
#include "main-func.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

#define TEST_DATA_1 "liveupdate-test-data-1"
#define TEST_DATA_2 "liveupdate-test-data-2"
#define SESSION_MEMFD_DATA "luo-session-memfd-test-data"
#define SESSION_MEMFD_TOKEN UINT64_C(42)

static int do_store(const char *prefix) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF;
        int r;

        fd1 = memfd_new_and_seal("luo-test-1", TEST_DATA_1, strlen(TEST_DATA_1));
        if (fd1 < 0)
                return log_error_errno(fd1, "Failed to create memfd 1: %m");

        fd2 = memfd_new_and_seal("luo-test-2", TEST_DATA_2, strlen(TEST_DATA_2));
        if (fd2 < 0)
                return log_error_errno(fd2, "Failed to create memfd 2: %m");

        r = sd_pid_notify_with_fds(0, /* unset_environment= */ false, "FDSTORE=1\nFDNAME=testfd1", &fd1, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to store memfd 1 in fd store: %m");

        r = sd_pid_notify_with_fds(0, /* unset_environment= */ false, "FDSTORE=1\nFDNAME=testfd2", &fd2, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to store memfd 2 in fd store: %m");

        log_info("Stored 2 memfds in fd store.");

        /* Also request a LUO session, put a memfd in it, and store the session fd */
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        _cleanup_close_ int session_fd = -EBADF, session_memfd = -EBADF;
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        int fd_idx;

        // TODO: make sure this doesn't fail on 6.19/7.0

        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Manager");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to io.systemd.Manager: %m");

        r = sd_varlink_set_allow_fd_passing_input(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable varlink fd passing: %m");

        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Manager.AllocateLUOSession",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("name", strjoina(prefix, "-varlink")));
        if (r < 0)
                return log_error_errno(r, "Failed to call AllocateLUOSession: %m");
        if (!isempty(error_id))
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "AllocateLUOSession failed: %s", error_id);

        fd_idx = (int) sd_json_variant_integer(sd_json_variant_by_key(reply, "sessionFileDescriptor"));
        session_fd = sd_varlink_take_fd(vl, fd_idx);
        if (session_fd < 0)
                return log_error_errno(session_fd, "Failed to take session fd: %m");

        session_memfd = memfd_new_and_seal("session-test", SESSION_MEMFD_DATA, strlen(SESSION_MEMFD_DATA));
        if (session_memfd < 0)
                return log_error_errno(session_memfd, "Failed to create session memfd: %m");

        r = luo_session_preserve_fd(session_fd, session_memfd, SESSION_MEMFD_TOKEN);
        if (r < 0)
                return log_error_errno(r, "Failed to preserve memfd in session: %m");

        r = sd_pid_notifyf_with_fds(0, false, &session_fd, 1, "FDSTORE=1\nFDNAME=%s-varlink", prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to store session fd in fd store: %m");
        TAKE_FD(session_fd);

        log_info("Stored LUO session with memfd from varlink in fd store.");

        /* Also request a second LUO session via D-Bus */
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *bus_reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_close_ int dbus_session_fd = -EBADF, dbus_session_memfd = -EBADF;
        int dbus_fd;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "AllocateLUOSession",
                        &bus_error,
                        &bus_reply,
                        "s", strjoina(prefix, "-dbus"));
        if (r < 0)
                return log_error_errno(r, "D-Bus AllocateLUOSession call failed: %s", bus_error.message);

        r = sd_bus_message_read(bus_reply, "h", &dbus_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to read session fd from D-Bus reply: %m");

        dbus_session_fd = fcntl(dbus_fd, F_DUPFD_CLOEXEC, 3);
        if (dbus_session_fd < 0)
                return log_error_errno(errno, "Failed to dup D-Bus session fd: %m");

        dbus_session_memfd = memfd_new_and_seal("dbus-session-test", SESSION_MEMFD_DATA, strlen(SESSION_MEMFD_DATA));
        if (dbus_session_memfd < 0)
                return log_error_errno(dbus_session_memfd, "Failed to create D-Bus session memfd: %m");

        r = luo_session_preserve_fd(dbus_session_fd, dbus_session_memfd, SESSION_MEMFD_TOKEN);
        if (r < 0)
                return log_error_errno(r, "Failed to preserve memfd in D-Bus session: %m");

        r = sd_pid_notifyf_with_fds(0, false, &dbus_session_fd, 1, "FDSTORE=1\nFDNAME=%s-dbus", prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to store D-Bus session fd in fd store: %m");
        TAKE_FD(dbus_session_fd);

        log_info("Stored LUO session with memfd from D-Bus in fd store.");
        return 0;
}

static int do_check(const char *prefix) {
        const char *e;
        _cleanup_strv_free_ char **names = NULL;
        const char *varlink_fdname = strjoina(prefix, "-varlink");
        const char *dbus_fdname = strjoina(prefix, "-dbus");
        int n_fds;

        /* sd_listen_fds_with_names() checks LISTEN_PID which won't match since we're a child process.
         * Read LISTEN_FDS and LISTEN_FDNAMES directly from the environment instead. */
        e = getenv("LISTEN_FDS");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No LISTEN_FDS environment variable set!");

        int r = safe_atoi(e, &n_fds);
        if (r < 0)
                return log_error_errno(r, "Failed to parse LISTEN_FDS='%s': %m", e);
        if (n_fds == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No file descriptors in fd store after kexec!");

        log_info("Got %d fd(s) in fd store after kexec.", n_fds);

        /* Parse LISTEN_FDNAMES to match fds by name, not position */
        e = getenv("LISTEN_FDNAMES");
        if (e) {
                names = strv_split(e, ":");
                if (!names)
                        return log_oom();
        }

        static const struct {
                const char *name;
                const char *expected;
        } checks[] = {
                { "testfd1", TEST_DATA_1 },
                { "testfd2", TEST_DATA_2 },
        };

        for (size_t i = 0; i < ELEMENTSOF(checks); i++) {
                char buf[256];
                ssize_t n;
                int fd = -EBADF;

                /* Find the fd by name */
                STRV_FOREACH(name, names) {
                        int idx = (int) (name - names);
                        if (idx >= n_fds)
                                break;
                        if (streq(*name, checks[i].name)) {
                                fd = SD_LISTEN_FDS_START + idx;
                                break;
                        }
                }

                if (fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "fd '%s' not found in LISTEN_FDNAMES!", checks[i].name);

                /* memfds are sealed, so seek to start before reading */
                if (lseek(fd, 0, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek fd %d: %m", fd);

                n = read(fd, buf, sizeof(buf) - 1);
                if (n < 0)
                        return log_error_errno(errno, "Failed to read fd %d: %m", fd);

                buf[n] = '\0';

                if (!streq(buf, checks[i].expected))
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EBADMSG),
                                        "Content mismatch for '%s': expected '%s', got '%s'",
                                        checks[i].name, checks[i].expected, buf);

                log_info("Verified fd '%s': content matches.", checks[i].name);
        }

        log_info("All fd store checks passed.");

        /* Also verify the LUO session fd survived and its memfd content is intact */
        int session_fd = -EBADF;
        STRV_FOREACH(name, names) {
                int idx = (int) (name - names);
                if (idx >= n_fds)
                        break;
                if (streq(*name, varlink_fdname)) {
                        session_fd = SD_LISTEN_FDS_START + idx;
                        break;
                }
        }

        if (session_fd < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "LUO session fd '%s' not found in fd store!", varlink_fdname);

        r = fd_is_luo_session(session_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if fd is LUO session: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "fd '%s' is not a LUO session!", varlink_fdname);

        _cleanup_close_ int session_memfd = luo_session_retrieve_fd(session_fd, SESSION_MEMFD_TOKEN);
        if (session_memfd < 0)
                return log_error_errno(session_memfd, "Failed to retrieve memfd from session: %m");

        char sbuf[256];
        if (lseek(session_memfd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek session memfd: %m");

        ssize_t sn = read(session_memfd, sbuf, sizeof(sbuf) - 1);
        if (sn < 0)
                return log_error_errno(errno, "Failed to read session memfd: %m");
        sbuf[sn] = '\0';

        if (!streq(sbuf, SESSION_MEMFD_DATA))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Session memfd content mismatch: expected '%s', got '%s'",
                                       SESSION_MEMFD_DATA, sbuf);

        log_info("Verified LUO session memfd from varlink content matches.");

        /* Also verify the D-Bus-allocated LUO session */
        int dbus_session_fd = -EBADF;
        STRV_FOREACH(name, names) {
                int idx = (int) (name - names);
                if (idx >= n_fds)
                        break;
                if (streq(*name, dbus_fdname)) {
                        dbus_session_fd = SD_LISTEN_FDS_START + idx;
                        break;
                }
        }

        if (dbus_session_fd < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "D-Bus LUO session fd '%s' not found in fd store!", dbus_fdname);

        r = fd_is_luo_session(dbus_session_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if D-Bus fd is LUO session: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "fd '%s' is not a LUO session!", dbus_fdname);

        _cleanup_close_ int dbus_memfd = luo_session_retrieve_fd(dbus_session_fd, SESSION_MEMFD_TOKEN);
        if (dbus_memfd < 0)
                return log_error_errno(dbus_memfd, "Failed to retrieve memfd from D-Bus session: %m");

        char dbuf[256];
        if (lseek(dbus_memfd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek D-Bus session memfd: %m");

        ssize_t dn = read(dbus_memfd, dbuf, sizeof(dbuf) - 1);
        if (dn < 0)
                return log_error_errno(errno, "Failed to read D-Bus session memfd: %m");
        dbuf[dn] = '\0';

        if (!streq(dbuf, SESSION_MEMFD_DATA))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "D-Bus session memfd content mismatch: expected '%s', got '%s'",
                                       SESSION_MEMFD_DATA, dbuf);

        log_info("Verified LUO session memfd from D-Bus content matches.");
        return 0;
}

static int run(int argc, char *argv[]) {
        if (argc < 2 || argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Usage: %s store|check [PREFIX]", argv[0]);

        const char *prefix = argc > 2 ? argv[2] : "luosession";

        if (streq(argv[1], "store"))
                return do_store(prefix);
        if (streq(argv[1], "check"))
                return do_check(prefix);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command: %s", argv[1]);
}

DEFINE_MAIN_FUNCTION(run);
