/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Helper for TEST-90-LIVEUPDATE: creates memfds and stores them in the fd store,
 * or verifies that inherited fd store entries contain the expected content.
 *
 * Usage:
 *   test-luo store   - create memfds with test data and push them to the fd store
 *   test-luo check   - verify fd store content matches expectations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "luo-util.h"
#include "main-func.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

#define TEST_DATA_1 "liveupdate-test-data-1"
#define TEST_DATA_2 "liveupdate-test-data-2"

static int do_store(void) {
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
        return 0;
}

static int do_check(void) {
        const char *e;
        _cleanup_strv_free_ char **names = NULL;
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
        return 0;
}

static int do_check_sessions(int argc, char *argv[]) {
        const char *e;
        _cleanup_strv_free_ char **names = NULL;
        int n_fds, n_verified = 0;

        /* Verify that named LUO sessions are present in the fd store */
        e = getenv("LISTEN_FDS");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No LISTEN_FDS environment variable set!");

        int r = safe_atoi(e, &n_fds);
        if (r < 0)
                return log_error_errno(r, "Failed to parse LISTEN_FDS='%s': %m", e);

        e = getenv("LISTEN_FDNAMES");
        if (e) {
                names = strv_split(e, ":");
                if (!names)
                        return log_oom();
        }

        for (int i = 2; i < argc; i++) {
                const char *session_name = argv[i];
                int fd = -EBADF;

                /* Find the fd by name */
                STRV_FOREACH(name, names) {
                        int idx = (int) (name - names);
                        if (idx >= n_fds)
                                break;
                        if (streq(*name, session_name)) {
                                fd = SD_LISTEN_FDS_START + idx;
                                break;
                        }
                }

                if (fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "LUO session '%s' not found in fd store!", session_name);

                r = fd_is_luo_session(fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if fd '%s' is a LUO session: %m", session_name);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "fd '%s' is not a LUO session!", session_name);

                log_info("Verified LUO session '%s' is present and valid.", session_name);
                n_verified++;
        }

        log_info("All %d LUO session(s) verified.", n_verified);
        return 0;
}

static int run(int argc, char *argv[]) {
        if (argc < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Usage: %s store|check|check-sessions NAME...", argv[0]);

        if (streq(argv[1], "store"))
                return do_store();
        if (streq(argv[1], "check"))
                return do_check();
        if (streq(argv[1], "check-sessions"))
                return do_check_sessions(argc, argv);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command: %s", argv[1]);
}

DEFINE_MAIN_FUNCTION(run);
