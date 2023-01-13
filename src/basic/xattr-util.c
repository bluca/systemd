/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/xattr.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "macro.h"
#include "missing_syscall.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"
#include "xattr-util.h"

int getxattr_malloc(
                const char *path,
                const char *name,
                char **ret,
                bool allow_symlink) {

        size_t l = 100;

        assert(path);
        assert(name);
        assert(ret);

        for(;;) {
                _cleanup_free_ char *v = NULL;
                ssize_t n;

                v = new0(char, l+1);
                if (!v)
                        return -ENOMEM;

                if (allow_symlink)
                        n = lgetxattr(path, name, v, l);
                else
                        n = getxattr(path, name, v, l);
                if (n < 0) {
                        if (errno != ERANGE)
                                return -errno;
                } else {
                        v[n] = 0; /* NUL terminate */
                        *ret = TAKE_PTR(v);
                        return (int) n;
                }

                if (allow_symlink)
                        n = lgetxattr(path, name, NULL, 0);
                else
                        n = getxattr(path, name, NULL, 0);
                if (n < 0)
                        return -errno;
                if (n > INT_MAX) /* We couldn't return this as 'int' anymore */
                        return -E2BIG;

                l = (size_t) n;
        }
}

int fgetxattr_malloc(
                int fd,
                const char *name,
                char **ret) {

        size_t l = 100;

        assert(fd >= 0);
        assert(name);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *v = NULL;
                ssize_t n;

                v = new(char, l+1);
                if (!v)
                        return -ENOMEM;

                n = fgetxattr(fd, name, v, l);
                if (n < 0) {
                        if (errno != ERANGE)
                                return -errno;
                } else {
                        v[n] = 0; /* NUL terminate */
                        *ret = TAKE_PTR(v);
                        return (int) n;
                }

                n = fgetxattr(fd, name, NULL, 0);
                if (n < 0)
                        return -errno;
                if (n > INT_MAX) /* We couldn't return this as 'int' anymore */
                        return -E2BIG;

                l = (size_t) n;
        }
}

/* Note: ret_fn should already be allocated for the usual xsprintf and /proc/self/fd/%i pattern. */
static int getxattrat_fake_prepare(
                int dirfd,
                const char *filename,
                int flags,
                char ret_fn[static STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1],
                int *ret_fd) {

        _cleanup_close_ int fd = -1;

        assert(ret_fn);
        assert(ret_fd);

        /* The kernel doesn't have a fgetxattrat() command, hence let's emulate one */

        if (flags & ~(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH))
                return -EINVAL;

        if (isempty(filename)) {
                if (!(flags & AT_EMPTY_PATH))
                        return -EINVAL;

                snprintf(ret_fn, STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1, "/proc/self/fd/%i", dirfd);
        } else {
                fd = openat(dirfd, filename, O_CLOEXEC|O_PATH|(flags & AT_SYMLINK_NOFOLLOW ? O_NOFOLLOW : 0));
                if (fd < 0)
                        return -errno;

                snprintf(ret_fn, STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1, "/proc/self/fd/%i", fd);
        }

        /* Pass the FD to the caller, since in case we do openat() the filename depends on it. */
        *ret_fd = TAKE_FD(fd);

        return 0;
}

int fgetxattrat_fake(
                int dirfd,
                const char *filename,
                const char *attribute,
                void *value, size_t size,
                int flags,
                size_t *ret_size) {

        char fn[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1];
        _cleanup_close_ int fd = -1;
        ssize_t l;
        int r;

        r = getxattrat_fake_prepare(dirfd, filename, flags, fn, &fd);
        if (r < 0)
                return r;

        l = getxattr(fn, attribute, value, size);
        if (l < 0)
                return -errno;

        *ret_size = l;
        return 0;
}

int fgetxattrat_fake_malloc(
                int dirfd,
                const char *filename,
                const char *attribute,
                int flags,
                char **value) {

        char fn[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1];
        _cleanup_close_ int fd = -1;
        int r;

        r = getxattrat_fake_prepare(dirfd, filename, flags, fn, &fd);
        if (r < 0)
                return r;

        return getxattr_malloc(fn, attribute, value, false);
}

static int parse_crtime(le64_t le, usec_t *usec) {
        uint64_t u;

        assert(usec);

        u = le64toh(le);
        if (IN_SET(u, 0, (uint64_t) -1))
                return -EIO;

        *usec = (usec_t) u;
        return 0;
}

int fd_getcrtime_at(int dirfd, const char *name, usec_t *ret, int flags) {
        STRUCT_STATX_DEFINE(sx);
        usec_t a, b;
        le64_t le;
        size_t n;
        int r;

        assert(ret);

        if (flags & ~(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW))
                return -EINVAL;

        /* So here's the deal: the creation/birth time (crtime/btime) of a file is a relatively newly supported concept
         * on Linux (or more strictly speaking: a concept that only recently got supported in the API, it was
         * implemented on various file systems on the lower level since a while, but never was accessible). However, we
         * needed a concept like that for vaccuuming algorithms and such, hence we emulated it via a user xattr for a
         * long time. Starting with Linux 4.11 there's statx() which exposes the timestamp to userspace for the first
         * time, where it is available. Thius function will read it, but it tries to keep some compatibility with older
         * systems: we try to read both the crtime/btime and the xattr, and then use whatever is older. After all the
         * concept is useful for determining how "old" a file really is, and hence using the older of the two makes
         * most sense. */

        if (statx(dirfd, strempty(name), flags|AT_STATX_DONT_SYNC, STATX_BTIME, &sx) >= 0 &&
            (sx.stx_mask & STATX_BTIME) &&
            sx.stx_btime.tv_sec != 0)
                a = (usec_t) sx.stx_btime.tv_sec * USEC_PER_SEC +
                        (usec_t) sx.stx_btime.tv_nsec / NSEC_PER_USEC;
        else
                a = USEC_INFINITY;

        r = fgetxattrat_fake(dirfd, name, "user.crtime_usec", &le, sizeof(le), flags, &n);
        if (r >= 0) {
                if (n != sizeof(le))
                        r = -EIO;
                else
                        r = parse_crtime(le, &b);
        }
        if (r < 0) {
                if (a != USEC_INFINITY) {
                        *ret = a;
                        return 0;
                }

                return r;
        }

        if (a != USEC_INFINITY)
                *ret = MIN(a, b);
        else
                *ret = b;

        return 0;
}

int fd_getcrtime(int fd, usec_t *ret) {
        return fd_getcrtime_at(fd, NULL, ret, AT_EMPTY_PATH);
}

int path_getcrtime(const char *p, usec_t *ret) {
        return fd_getcrtime_at(AT_FDCWD, p, ret, 0);
}

int fd_setcrtime(int fd, usec_t usec) {
        le64_t le;

        assert(fd >= 0);

        if (IN_SET(usec, 0, USEC_INFINITY))
                usec = now(CLOCK_REALTIME);

        le = htole64((uint64_t) usec);
        if (fsetxattr(fd, "user.crtime_usec", &le, sizeof(le), 0) < 0)
                return -errno;

        return 0;
}

int flistxattr_malloc(int fd, char **ret) {
        size_t l = 100;

        assert(fd >= 0);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *v = NULL;
                ssize_t n;

                v = new(char, l+1);
                if (!v)
                        return -ENOMEM;

                n = flistxattr(fd, v, l);
                if (n < 0) {
                        if (errno != ERANGE)
                                return -errno;
                } else {
                        v[n] = 0; /* NUL terminate */
                        *ret = TAKE_PTR(v);
                        return (int) n;
                }

                n = flistxattr(fd, NULL, 0);
                if (n < 0)
                        return -errno;
                if (n > INT_MAX) /* We couldn't return this as 'int' anymore */
                        return -E2BIG;

                l = (size_t) n;
        }
}
