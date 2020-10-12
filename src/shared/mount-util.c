/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <linux/loop.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dissect-image.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "libmount-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

int umount_recursive(const char *prefix, int flags) {
        int n = 0, r;
        bool again;

        /* Try to umount everything recursively below a
         * directory. Also, take care of stacked mounts, and keep
         * unmounting them until they are gone. */

        do {
                _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;

                again = false;

                r = libmount_parse("/proc/self/mountinfo", NULL, &table, &iter);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

                for (;;) {
                        struct libmnt_fs *fs;
                        const char *path;

                        r = mnt_table_next_fs(table, iter, &fs);
                        if (r == 1)
                                break;
                        if (r < 0)
                                return log_debug_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                        path = mnt_fs_get_target(fs);
                        if (!path)
                                continue;

                        if (!path_startswith(path, prefix))
                                continue;

                        if (umount2(path, flags) < 0) {
                                r = log_debug_errno(errno, "Failed to umount %s: %m", path);
                                continue;
                        }

                        log_debug("Successfully unmounted %s", path);

                        again = true;
                        n++;

                        break;
                }

        } while (again);

        return n;
}

/* Get the mount flags for the mountpoint at "path" from "table" */
static int get_mount_flags(const char *path, unsigned long *flags, struct libmnt_table *table) {
        struct statvfs buf = {};
        struct libmnt_fs *fs = NULL;
        const char *opts = NULL;
        int r = 0;

        fs = mnt_table_find_target(table, path, MNT_ITER_FORWARD);
        if (!fs) {
                log_warning("Could not find '%s' in mount table", path);
                goto fallback;
        }

        opts = mnt_fs_get_vfs_options(fs);
        r = mnt_optstr_get_flags(opts, flags, mnt_get_builtin_optmap(MNT_LINUX_MAP));
        if (r != 0) {
                log_warning_errno(r, "Could not get flags for '%s': %m", path);
                goto fallback;
        }

        /* relatime is default and trying to set it in an unprivileged container causes EPERM */
        *flags &= ~MS_RELATIME;
        return 0;

fallback:
        if (statvfs(path, &buf) < 0)
                return -errno;

        *flags = buf.f_flag;
        return 0;
}

/* Use this function only if you do not have direct access to /proc/self/mountinfo but the caller can open it
 * for you. This is the case when /proc is masked or not mounted. Otherwise, use bind_remount_recursive. */
int bind_remount_recursive_with_mountinfo(
                const char *prefix,
                unsigned long new_flags,
                unsigned long flags_mask,
                char **blacklist,
                FILE *proc_self_mountinfo) {

        _cleanup_set_free_free_ Set *done = NULL;
        _cleanup_free_ char *cleaned = NULL;
        int r;

        assert(proc_self_mountinfo);

        /* Recursively remount a directory (and all its submounts) read-only or read-write. If the directory is already
         * mounted, we reuse the mount and simply mark it MS_BIND|MS_RDONLY (or remove the MS_RDONLY for read-write
         * operation). If it isn't we first make it one. Afterwards we apply MS_BIND|MS_RDONLY (or remove MS_RDONLY) to
         * all submounts we can access, too. When mounts are stacked on the same mount point we only care for each
         * individual "top-level" mount on each point, as we cannot influence/access the underlying mounts anyway. We
         * do not have any effect on future submounts that might get propagated, they migt be writable. This includes
         * future submounts that have been triggered via autofs.
         *
         * If the "blacklist" parameter is specified it may contain a list of subtrees to exclude from the
         * remount operation. Note that we'll ignore the blacklist for the top-level path. */

        cleaned = strdup(prefix);
        if (!cleaned)
                return -ENOMEM;

        path_simplify(cleaned, false);

        done = set_new(&path_hash_ops);
        if (!done)
                return -ENOMEM;

        for (;;) {
                _cleanup_set_free_free_ Set *todo = NULL;
                _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
                bool top_autofs = false;
                char *x;
                unsigned long orig_flags;

                todo = set_new(&path_hash_ops);
                if (!todo)
                        return -ENOMEM;

                rewind(proc_self_mountinfo);

                r = libmount_parse("/proc/self/mountinfo", proc_self_mountinfo, &table, &iter);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

                for (;;) {
                        struct libmnt_fs *fs;
                        const char *path, *type;

                        r = mnt_table_next_fs(table, iter, &fs);
                        if (r == 1)
                                break;
                        if (r < 0)
                                return log_debug_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                        path = mnt_fs_get_target(fs);
                        type = mnt_fs_get_fstype(fs);
                        if (!path || !type)
                                continue;

                        if (!path_startswith(path, cleaned))
                                continue;

                        /* Ignore this mount if it is blacklisted, but only if it isn't the top-level mount
                         * we shall operate on. */
                        if (!path_equal(path, cleaned)) {
                                bool blacklisted = false;
                                char **i;

                                STRV_FOREACH(i, blacklist) {
                                        if (path_equal(*i, cleaned))
                                                continue;

                                        if (!path_startswith(*i, cleaned))
                                                continue;

                                        if (path_startswith(path, *i)) {
                                                blacklisted = true;
                                                log_debug("Not remounting %s blacklisted by %s, called for %s",
                                                          path, *i, cleaned);
                                                break;
                                        }
                                }
                                if (blacklisted)
                                        continue;
                        }

                        /* Let's ignore autofs mounts.  If they aren't
                         * triggered yet, we want to avoid triggering
                         * them, as we don't make any guarantees for
                         * future submounts anyway.  If they are
                         * already triggered, then we will find
                         * another entry for this. */
                        if (streq(type, "autofs")) {
                                top_autofs = top_autofs || path_equal(path, cleaned);
                                continue;
                        }

                        if (!set_contains(done, path)) {
                                r = set_put_strdup(todo, path);
                                if (r < 0)
                                        return r;
                        }
                }

                /* If we have no submounts to process anymore and if
                 * the root is either already done, or an autofs, we
                 * are done */
                if (set_isempty(todo) &&
                    (top_autofs || set_contains(done, cleaned)))
                        return 0;

                if (!set_contains(done, cleaned) &&
                    !set_contains(todo, cleaned)) {
                        /* The prefix directory itself is not yet a mount, make it one. */
                        if (mount(cleaned, cleaned, NULL, MS_BIND|MS_REC, NULL) < 0)
                                return -errno;

                        orig_flags = 0;
                        (void) get_mount_flags(cleaned, &orig_flags, table);
                        orig_flags &= ~MS_RDONLY;

                        if (mount(NULL, cleaned, NULL, (orig_flags & ~flags_mask)|MS_BIND|MS_REMOUNT|new_flags, NULL) < 0)
                                return -errno;

                        log_debug("Made top-level directory %s a mount point.", prefix);

                        r = set_put_strdup(done, cleaned);
                        if (r < 0)
                                return r;
                }

                while ((x = set_steal_first(todo))) {

                        r = set_consume(done, x);
                        if (IN_SET(r, 0, -EEXIST))
                                continue;
                        if (r < 0)
                                return r;

                        /* Deal with mount points that are obstructed by a later mount */
                        r = path_is_mount_point(x, NULL, 0);
                        if (IN_SET(r, 0, -ENOENT))
                                continue;
                        if (IN_SET(r, -EACCES, -EPERM)) {
                                /* Even if root user invoke this, submounts under private FUSE or NFS mount points
                                 * may not be acceessed. E.g.,
                                 *
                                 * $ bindfs --no-allow-other ~/mnt/mnt ~/mnt/mnt
                                 * $ bindfs --no-allow-other ~/mnt ~/mnt
                                 *
                                 * Then, root user cannot access the mount point ~/mnt/mnt.
                                 * In such cases, the submounts are ignored, as we have no way to manage them. */
                                log_debug_errno(r, "Failed to determine '%s' is mount point or not, ignoring: %m", x);
                                continue;
                        }
                        if (r < 0)
                                return r;

                        /* Try to reuse the original flag set */
                        orig_flags = 0;
                        (void) get_mount_flags(x, &orig_flags, table);
                        orig_flags &= ~MS_RDONLY;

                        if (mount(NULL, x, NULL, (orig_flags & ~flags_mask)|MS_BIND|MS_REMOUNT|new_flags, NULL) < 0)
                                return -errno;

                        log_debug("Remounted %s read-only.", x);
                }
        }
}

int bind_remount_recursive(const char *prefix, unsigned long new_flags, unsigned long flags_mask, char **blacklist) {
        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
        int r;

        r = fopen_unlocked("/proc/self/mountinfo", "re", &proc_self_mountinfo);
        if (r < 0)
                return r;

        return bind_remount_recursive_with_mountinfo(prefix, new_flags, flags_mask, blacklist, proc_self_mountinfo);
}

int mount_move_root(const char *path) {
        assert(path);

        if (chdir(path) < 0)
                return -errno;

        if (mount(path, "/", NULL, MS_MOVE, NULL) < 0)
                return -errno;

        if (chroot(".") < 0)
                return -errno;

        if (chdir("/") < 0)
                return -errno;

        return 0;
}

int repeat_unmount(const char *path, int flags) {
        bool done = false;

        assert(path);

        /* If there are multiple mounts on a mount point, this
         * removes them all */

        for (;;) {
                if (umount2(path, flags) < 0) {

                        if (errno == EINVAL)
                                return done;

                        return -errno;
                }

                done = true;
        }
}

const char* mode_to_inaccessible_node(mode_t mode) {
        /* This function maps a node type to a corresponding inaccessible file node. These nodes are created during
         * early boot by PID 1. In some cases we lacked the privs to create the character and block devices (maybe
         * because we run in an userns environment, or miss CAP_SYS_MKNOD, or run with a devices policy that excludes
         * device nodes with major and minor of 0), but that's fine, in that case we use an AF_UNIX file node instead,
         * which is not the same, but close enough for most uses. And most importantly, the kernel allows bind mounts
         * from socket nodes to any non-directory file nodes, and that's the most important thing that matters. */

        switch(mode & S_IFMT) {
                case S_IFREG:
                        return "/run/systemd/inaccessible/reg";

                case S_IFDIR:
                        return "/run/systemd/inaccessible/dir";

                case S_IFCHR:
                        if (access("/run/systemd/inaccessible/chr", F_OK) == 0)
                                return "/run/systemd/inaccessible/chr";
                        return "/run/systemd/inaccessible/sock";

                case S_IFBLK:
                        if (access("/run/systemd/inaccessible/blk", F_OK) == 0)
                                return "/run/systemd/inaccessible/blk";
                        return "/run/systemd/inaccessible/sock";

                case S_IFIFO:
                        return "/run/systemd/inaccessible/fifo";

                case S_IFSOCK:
                        return "/run/systemd/inaccessible/sock";
        }
        return NULL;
}

#define FLAG(name) (flags & name ? STRINGIFY(name) "|" : "")
static char* mount_flags_to_string(long unsigned flags) {
        char *x;
        _cleanup_free_ char *y = NULL;
        long unsigned overflow;

        overflow = flags & ~(MS_RDONLY |
                             MS_NOSUID |
                             MS_NODEV |
                             MS_NOEXEC |
                             MS_SYNCHRONOUS |
                             MS_REMOUNT |
                             MS_MANDLOCK |
                             MS_DIRSYNC |
                             MS_NOATIME |
                             MS_NODIRATIME |
                             MS_BIND |
                             MS_MOVE |
                             MS_REC |
                             MS_SILENT |
                             MS_POSIXACL |
                             MS_UNBINDABLE |
                             MS_PRIVATE |
                             MS_SLAVE |
                             MS_SHARED |
                             MS_RELATIME |
                             MS_KERNMOUNT |
                             MS_I_VERSION |
                             MS_STRICTATIME |
                             MS_LAZYTIME);

        if (flags == 0 || overflow != 0)
                if (asprintf(&y, "%lx", overflow) < 0)
                        return NULL;

        x = strjoin(FLAG(MS_RDONLY),
                    FLAG(MS_NOSUID),
                    FLAG(MS_NODEV),
                    FLAG(MS_NOEXEC),
                    FLAG(MS_SYNCHRONOUS),
                    FLAG(MS_REMOUNT),
                    FLAG(MS_MANDLOCK),
                    FLAG(MS_DIRSYNC),
                    FLAG(MS_NOATIME),
                    FLAG(MS_NODIRATIME),
                    FLAG(MS_BIND),
                    FLAG(MS_MOVE),
                    FLAG(MS_REC),
                    FLAG(MS_SILENT),
                    FLAG(MS_POSIXACL),
                    FLAG(MS_UNBINDABLE),
                    FLAG(MS_PRIVATE),
                    FLAG(MS_SLAVE),
                    FLAG(MS_SHARED),
                    FLAG(MS_RELATIME),
                    FLAG(MS_KERNMOUNT),
                    FLAG(MS_I_VERSION),
                    FLAG(MS_STRICTATIME),
                    FLAG(MS_LAZYTIME),
                    y);
        if (!x)
                return NULL;
        if (!y)
                x[strlen(x) - 1] = '\0'; /* truncate the last | */
        return x;
}

int mount_verbose(
                int error_log_level,
                const char *what,
                const char *where,
                const char *type,
                unsigned long flags,
                const char *options) {

        _cleanup_free_ char *fl = NULL, *o = NULL;
        unsigned long f;
        int r;

        r = mount_option_mangle(options, flags, &f, &o);
        if (r < 0)
                return log_full_errno(error_log_level, r,
                                      "Failed to mangle mount options %s: %m",
                                      strempty(options));

        fl = mount_flags_to_string(f);

        if ((f & MS_REMOUNT) && !what && !type)
                log_debug("Remounting %s (%s \"%s\")...",
                          where, strnull(fl), strempty(o));
        else if (!what && !type)
                log_debug("Mounting %s (%s \"%s\")...",
                          where, strnull(fl), strempty(o));
        else if ((f & MS_BIND) && !type)
                log_debug("Bind-mounting %s on %s (%s \"%s\")...",
                          what, where, strnull(fl), strempty(o));
        else if (f & MS_MOVE)
                log_debug("Moving mount %s → %s (%s \"%s\")...",
                          what, where, strnull(fl), strempty(o));
        else
                log_debug("Mounting %s on %s (%s \"%s\")...",
                          strna(type), where, strnull(fl), strempty(o));
        if (mount(what, where, type, f, o) < 0)
                return log_full_errno(error_log_level, errno,
                                      "Failed to mount %s (type %s) on %s (%s \"%s\"): %m",
                                      strna(what), strna(type), where, strnull(fl), strempty(o));
        return 0;
}

int umount_verbose(const char *what) {
        log_debug("Umounting %s...", what);
        if (umount(what) < 0)
                return log_error_errno(errno, "Failed to unmount %s: %m", what);
        return 0;
}

int mount_option_mangle(
                const char *options,
                unsigned long mount_flags,
                unsigned long *ret_mount_flags,
                char **ret_remaining_options) {

        const struct libmnt_optmap *map;
        _cleanup_free_ char *ret = NULL;
        const char *p;
        int r;

        /* This extracts mount flags from the mount options, and store
         * non-mount-flag options to '*ret_remaining_options'.
         * E.g.,
         * "rw,nosuid,nodev,relatime,size=1630748k,mode=700,uid=1000,gid=1000"
         * is split to MS_NOSUID|MS_NODEV|MS_RELATIME and
         * "size=1630748k,mode=700,uid=1000,gid=1000".
         * See more examples in test-mount-utils.c.
         *
         * Note that if 'options' does not contain any non-mount-flag options,
         * then '*ret_remaining_options' is set to NULL instead of empty string.
         * Note that this does not check validity of options stored in
         * '*ret_remaining_options'.
         * Note that if 'options' is NULL, then this just copies 'mount_flags'
         * to '*ret_mount_flags'. */

        assert(ret_mount_flags);
        assert(ret_remaining_options);

        map = mnt_get_builtin_optmap(MNT_LINUX_MAP);
        if (!map)
                return -EINVAL;

        p = options;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                const struct libmnt_optmap *ent;

                r = extract_first_word(&p, &word, ",", EXTRACT_UNQUOTE);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                for (ent = map; ent->name; ent++) {
                        /* All entries in MNT_LINUX_MAP do not take any argument.
                         * Thus, ent->name does not contain "=" or "[=]". */
                        if (!streq(word, ent->name))
                                continue;

                        if (!(ent->mask & MNT_INVERT))
                                mount_flags |= ent->id;
                        else if (mount_flags & ent->id)
                                mount_flags ^= ent->id;

                        break;
                }

                /* If 'word' is not a mount flag, then store it in '*ret_remaining_options'. */
                if (!ent->name && !strextend_with_separator(&ret, ",", word, NULL))
                        return -ENOMEM;
        }

        *ret_mount_flags = mount_flags;
        *ret_remaining_options = TAKE_PTR(ret);

        return 0;
}

int bind_mount_in_namespace(
                pid_t target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                int read_only,
                int make_file_or_directory,
                char **inaccessible_paths,
                char **error_path) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        _cleanup_close_ int self_mntns_fd = -1, mntns_fd = -1, root_fd = -1;
        char mount_slave[] = "/tmp/propagate.XXXXXX", *mount_tmp, *mount_outside, *p, **inaccessible;
        bool mount_slave_created = false, mount_slave_mounted = false,
                mount_tmp_created = false, mount_tmp_mounted = false,
                mount_outside_created = false, mount_outside_mounted = false;
        _cleanup_free_ char *chased_src = NULL, *self_mntns = NULL, *mntns = NULL;
        struct stat st;
        pid_t child;
        int r;

        assert(target > 0);
        assert(propagate_path);
        assert(incoming_path);
        assert(src);
        assert(dest);

        /* If it would be dropped at startup time, skip it */
        STRV_FOREACH(inaccessible, inaccessible_paths)
                if (path_startswith(dest, *inaccessible)) {
                        if (error_path)
                                *error_path = strjoin(dest, " is not accessible");
                        return -EINVAL;
                }

        r = namespace_open(target, NULL, &mntns_fd, NULL, NULL, &root_fd);
        if (r < 0)
                return r;

        r = fd_get_path(mntns_fd, &mntns);
        if (r < 0)
                return r;

        r = namespace_open(getpid(), NULL, &self_mntns_fd, NULL, NULL, NULL);
        if (r < 0)
                return r;

        r = fd_get_path(self_mntns_fd, &self_mntns);
        if (r < 0)
                return r;

        /* We can't add new mounts at runtime if the process wasn't started in a namespace */
        if (streq(self_mntns, mntns)) {
                if (error_path)
                        *error_path = strdup("Failed to activate bind mount in target, not running in a mount namespace");
                return -EINVAL;
        }

        /* One day, when bind mounting /proc/self/fd/n works across
         * namespace boundaries we should rework this logic to make
         * use of it... */

        p = strjoina(propagate_path, "/");
        if (laccess(p, F_OK) < 0) {
                if (error_path)
                        *error_path = strdup("Target does not allow propagation of mount points.");
                return -EOPNOTSUPP;
        }

        r = chase_symlinks(src, NULL, CHASE_TRAIL_SLASH, &chased_src, NULL);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to resolve source path");
                return r;
        }

        if (lstat(chased_src, &st) < 0) {
                if (error_path)
                        *error_path = strdup("Failed to stat() source path");
                return -errno;
        }
        if (S_ISLNK(st.st_mode)) /* This shouldn't really happen, given that we just chased the symlinks above, but let's better be safe… */ {
                if (error_path)
                        *error_path = strdup("Source directory can't be a symbolic link");
                return -EOPNOTSUPP;
        }

        /* Our goal is to install a new bind mount into the container,
           possibly read-only. This is irritatingly complex
           unfortunately, currently.

           First, we start by creating a private playground in /tmp,
           that we can mount MS_SLAVE. (Which is necessary, since
           MS_MOVE cannot be applied to mounts with MS_SHARED parent
           mounts.) */

        if (!mkdtemp(mount_slave)) {
                if (error_path)
                        *error_path = strjoin("Failed to create playground ", mount_slave);
                return -errno;
        }

        mount_slave_created = true;

        if (mount(mount_slave, mount_slave, NULL, MS_BIND, NULL) < 0) {
                r = -errno;
                if (error_path)
                        *error_path = strjoin("Failed to make bind mount ", mount_slave);
                goto finish;
        }

        mount_slave_mounted = true;

        if (mount(NULL, mount_slave, NULL, MS_SLAVE, NULL) < 0) {
                r = -errno;
                if (error_path)
                        *error_path = strjoin("Failed to remount slave ", mount_slave);
                goto finish;
        }

        /* Second, we mount the source file or directory to a directory inside of our MS_SLAVE playground. */
        mount_tmp = strjoina(mount_slave, "/mount");
        if (S_ISDIR(st.st_mode))
                r = mkdir_errno_wrapper(mount_tmp, 0700);
        else
                r = touch(mount_tmp);
        if (r < 0) {
                if (error_path)
                        *error_path = strjoin("Failed to create temporary mount point ", mount_tmp);
                goto finish;
        }

        mount_tmp_created = true;

        if (mount(chased_src, mount_tmp, NULL, MS_BIND, NULL) < 0) {
                r = -errno;
                if (error_path)
                        *error_path = strjoin("Failed to mount ", chased_src);
                goto finish;
        }

        mount_tmp_mounted = true;

        /* Third, we remount the new bind mount read-only if requested. */
        if (read_only) {
                if (mount(NULL, mount_tmp, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) < 0) {
                        r = -errno;
                        if (error_path)
                                *error_path = strjoin("Failed to remount read-only ", mount_tmp);
                        goto finish;
                }
        }

        /* Fourth, we move the new bind mount into the propagation directory. This way it will appear there read-only
         * right-away. */

        mount_outside = strjoina(propagate_path, "/XXXXXX");
        if (S_ISDIR(st.st_mode))
                r = mkdtemp(mount_outside) ? 0 : -errno;
        else {
                r = mkostemp_safe(mount_outside);
                safe_close(r);
        }
        if (r < 0) {
                if (error_path)
                        *error_path = strjoin("Cannot create propagation file or directory ", mount_outside);
                goto finish;
        }

        mount_outside_created = true;

        if (mount(mount_tmp, mount_outside, NULL, MS_MOVE, NULL) < 0) {
                r = -errno;
                if (error_path)
                        *error_path = strjoin("Failed to move ", mount_tmp, " to ", mount_outside);
                goto finish;
        }

        mount_outside_mounted = true;
        mount_tmp_mounted = false;

        if (S_ISDIR(st.st_mode))
                (void) rmdir(mount_tmp);
        else
                (void) unlink(mount_tmp);
        mount_tmp_created = false;

        (void) umount(mount_slave);
        mount_slave_mounted = false;

        (void) rmdir(mount_slave);
        mount_slave_created = false;

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0) {
                if (error_path)
                        *error_path = strdup("Failed to create pipe");
                r = -errno;
                goto finish;
        }

        r = namespace_fork("(sd-bindmnt)", "(sd-bindmnt-inner)", NULL, 0, FORK_RESET_SIGNALS|FORK_DEATHSIG,
                           -1, mntns_fd, -1, -1, root_fd, &child);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to fork()");
                r = -errno;
                goto finish;
        }
        if (r == 0) {
                const char *mount_inside;

                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                if (make_file_or_directory) {
                        if (S_ISDIR(st.st_mode))
                                (void) mkdir_p(dest, 0755);
                        else {
                                (void) mkdir_parents(dest, 0755);
                                (void) mknod(dest, S_IFREG|0600, 0);
                        }
                }

                /* Fifth, move the mount to the right place inside */
                mount_inside = strjoina(incoming_path, basename(mount_outside));
                if (mount(mount_inside, dest, NULL, MS_MOVE, NULL) < 0) {
                        r = -errno;
                        goto child_fail;
                }

                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(errno_pipe_fd[1], &r, sizeof(r));
                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                _exit(EXIT_FAILURE);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = wait_for_terminate_and_check("(sd-bindmnt)", child, 0);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to wait for child");
                r = -errno;
                goto finish;
        }
        if (r != EXIT_SUCCESS) {
                if (read(errno_pipe_fd[0], &r, sizeof(r)) == sizeof(r)) {
                        if (error_path)
                                *error_path = strdup("Failed to mount");
                } else if (error_path)
                        *error_path = strdup("Child failed.");
                goto finish;
        }

finish:
        if (mount_outside_mounted)
                (void) umount(mount_outside);
        if (mount_outside_created) {
                if (S_ISDIR(st.st_mode))
                        (void) rmdir(mount_outside);
                else
                        (void) unlink(mount_outside);
        }

        if (mount_tmp_mounted)
                (void) umount(mount_tmp);
        if (mount_tmp_created) {
                if (S_ISDIR(st.st_mode))
                        (void) rmdir(mount_tmp);
                else
                        (void) unlink(mount_tmp);
        }

        if (mount_slave_mounted)
                (void) umount(mount_slave);
        if (mount_slave_created)
                (void) rmdir(mount_slave);

        return r;
}

int mount_image_in_namespace(
                pid_t target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                const MountOptions *options,
                int make_file_or_directory,
                char **error_path) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        _cleanup_close_ int self_mntns_fd = -1, mntns_fd = -1, root_fd = -1;
        char mount_slave[] = "/tmp/propagate.XXXXXX", *mount_tmp, *mount_outside, *p;
        bool mount_slave_created = false, mount_slave_mounted = false,
                mount_tmp_created = false, mount_tmp_mounted = false,
                mount_outside_created = false, mount_outside_mounted = false;
        _cleanup_free_ char *chased_src = NULL, *self_mntns = NULL, *mntns = NULL;
        struct stat st;
        pid_t child;
        int r;

        assert(target > 0);
        assert(propagate_path);
        assert(incoming_path);
        assert(src);

        r = namespace_open(target, NULL, &mntns_fd, NULL, NULL, &root_fd);
        if (r < 0)
                return r;

        r = fd_get_path(mntns_fd, &mntns);
        if (r < 0)
                return r;

        r = namespace_open(getpid(), NULL, &self_mntns_fd, NULL, NULL, NULL);
        if (r < 0)
                return r;

        r = fd_get_path(self_mntns_fd, &self_mntns);
        if (r < 0)
                return r;

        /* We can't add new mounts at runtime if the process wasn't started in a namespace */
        if (streq(self_mntns, mntns)) {
                if (error_path)
                        *error_path = strdup("Failed to activate bind mount in target, not running in a mount namespace");
                return -EINVAL;
        }

        /* One day, when bind mounting /proc/self/fd/n works across
         * namespace boundaries we should rework this logic to make
         * use of it... */

        p = strjoina(propagate_path, "/");
        if (laccess(p, F_OK) < 0) {
                if (error_path)
                        *error_path = strdup("Target does not allow propagation of mount points.");
                return -EOPNOTSUPP;
        }

        r = chase_symlinks(src, NULL, CHASE_TRAIL_SLASH, &chased_src, NULL);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to resolve source path");
                return r;
        }

        if (lstat(chased_src, &st) < 0) {
                if (error_path)
                        *error_path = strdup("Failed to stat() source path");
                return -errno;
        }
        if (S_ISLNK(st.st_mode)) /* This shouldn't really happen, given that we just chased the symlinks above, but let's better be safe… */ {
                if (error_path)
                        *error_path = strdup("Source directory can't be a symbolic link");
                return -EOPNOTSUPP;
        }

        /* Our goal is to install a new bind mount into the container,
           possibly read-only. This is irritatingly complex
           unfortunately, currently.

           First, we start by creating a private playground in /tmp,
           that we can mount MS_SLAVE. (Which is necessary, since
           MS_MOVE cannot be applied to mounts with MS_SHARED parent
           mounts.) */

        if (!mkdtemp(mount_slave)) {
                if (error_path)
                        *error_path = strjoin("Failed to create playground ", mount_slave);
                return -errno;
        }

        mount_slave_created = true;

        if (mount(mount_slave, mount_slave, NULL, MS_BIND, NULL) < 0) {
                r = -errno;
                if (error_path)
                        *error_path = strjoin("Failed to make bind mount ", mount_slave);
                goto finish;
        }

        mount_slave_mounted = true;

        if (mount(NULL, mount_slave, NULL, MS_SLAVE, NULL) < 0) {
                r = -errno;
                if (error_path)
                        *error_path = strjoin("Failed to remount slave ", mount_slave);
                goto finish;
        }

        /* Second, we mount the source file or directory to a directory inside of our MS_SLAVE playground. */
        mount_tmp = strjoina(mount_slave, "/mount");
        r = mkdir_errno_wrapper(mount_tmp, 0700);
        if (r < 0) {
                if (error_path)
                        *error_path = strjoin("Failed to create temporary mount point ", mount_tmp);
                goto finish;
        }

        mount_tmp_created = true;

        r = verity_dissect_and_mount(chased_src, mount_tmp, options, error_path);
        if (r < 0)
                goto finish;

        mount_tmp_mounted = true;

        /* Third, we move the new bind mount into the propagation directory. This way it will appear there read-only
         * right-away. */

        mount_outside = strjoina(propagate_path, "/XXXXXX");
        r = mkdtemp(mount_outside) ? 0 : -errno;
        if (r < 0) {
                if (error_path)
                        *error_path = strjoin("Cannot create propagation file or directory ", mount_outside);
                goto finish;
        }

        mount_outside_created = true;

        /* Overlay mount? We need an additional scratch directory inside the namespace, for the image */
        if (isempty(dest)) {
                r = mkdir_errno_wrapper(strjoina(mount_outside, "-inside"), 0700);
                if (r < 0) {
                        if (error_path)
                                *error_path = strjoin("Cannot create propagation file or directory ", mount_outside, "-inside");
                        goto finish;
                }
        }

        if (mount(mount_tmp, mount_outside, NULL, MS_MOVE, NULL) < 0) {
                r = -errno;
                if (error_path)
                        *error_path = strjoin("Failed to move ", mount_tmp, " to ", mount_outside);
                goto finish;
        }

        mount_outside_mounted = true;
        mount_tmp_mounted = false;

        (void) rmdir(mount_tmp);
        mount_tmp_created = false;

        (void) umount(mount_slave);
        mount_slave_mounted = false;

        (void) rmdir(mount_slave);
        mount_slave_created = false;

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0) {
                if (error_path)
                        *error_path = strdup("Failed to create pipe");
                r = -errno;
                goto finish;
        }

        r = namespace_fork("(sd-bindmnt)", "(sd-bindmnt-inner)", NULL, 0, FORK_RESET_SIGNALS|FORK_DEATHSIG,
                           -1, mntns_fd, -1, -1, root_fd, &child);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to fork()");
                r = -errno;
                goto finish;
        }
        if (r == 0) {
                _cleanup_strv_free_ char **mounts_list = NULL, **overlays_list = NULL;
                const char *mount_inside;
                char **q;

                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                mount_inside = strjoina(incoming_path, basename(mount_outside));

                /* Overlay mount? Move the image but keep it in the incoming directory */
                if (isempty(dest)) {
                        r = path_compute_overlays("/", mount_inside, &mounts_list, &overlays_list);
                        if (r < 0)
                                goto child_fail;

                        dest = strjoina(mount_inside, "-inside");
                } else if (make_file_or_directory)
                        (void) mkdir_p(dest, 0755);

                /* Fourth, move the mount to the right place inside */
                if (mount(mount_inside, dest, NULL, MS_MOVE, NULL) < 0) {
                        r = -errno;
                        goto child_fail;
                }

                STRV_FOREACH(q, mounts_list) {
                        _cleanup_free_ char *s = NULL;

                        s = path_join(dest, *q);
                        if (!s) {
                                r = -ENOMEM;
                                goto child_fail;
                        }

                        r = mount(s, *q, NULL, MS_BIND, NULL);
                        if (r < 0) {
                                r = -errno;
                                goto child_fail;
                        }
                }

                STRV_FOREACH(q, overlays_list) {
                        _cleanup_free_ char *s = NULL, *overlay_options = NULL;

                        s = path_join(dest, *q);
                        if (!s) {
                                r = -ENOMEM;
                                goto child_fail;
                        }

                        /* We only support read-only overlays, so no upper nor work directories */
                        overlay_options = strjoin("lowerdir=", s, ":", *q);
                        if (!overlay_options) {
                                r = -ENOMEM;
                                goto child_fail;
                        }

                        r = mount("overlay", *q, "overlay", MS_RDONLY, overlay_options);
                        if (r < 0) {
                                r = -errno;
                                goto child_fail;
                        }
                }

                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(errno_pipe_fd[1], &r, sizeof(r));
                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                _exit(EXIT_FAILURE);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = wait_for_terminate_and_check("(sd-bindmnt)", child, 0);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to wait for child");
                r = -errno;
                goto finish;
        }
        if (r != EXIT_SUCCESS) {
                if (read(errno_pipe_fd[0], &r, sizeof(r)) == sizeof(r)) {
                        if (error_path)
                                *error_path = strdup("Failed to mount");
                } else if (error_path)
                        *error_path = strdup("Child failed.");
                goto finish;
        }

finish:
        if (mount_outside_mounted)
                (void) umount(mount_outside);
        if (mount_outside_created)
                (void) rmdir(mount_outside);

        if (mount_tmp_mounted)
                (void) umount(mount_tmp);
        if (mount_tmp_created)
                (void) rmdir(mount_tmp);

        if (mount_slave_mounted)
                (void) umount(mount_slave);
        if (mount_slave_created)
                (void) rmdir(mount_slave);

        return r;
}
