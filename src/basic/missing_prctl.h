/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/prctl.h>

/* 58319057b7847667f0c9585b9de0e8932b0fdb08 (4.3) */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47

#define PR_CAP_AMBIENT_IS_SET    1
#define PR_CAP_AMBIENT_RAISE     2
#define PR_CAP_AMBIENT_LOWER     3
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

/* 7ac592aa35a684ff1858fb9ec282886b9e3575ac (5.14) */
#ifndef PR_SCHED_CORE
#define PR_SCHED_CORE 62

#define PR_SCHED_CORE_GET        0
#define PR_SCHED_CORE_CREATE     1
#define PR_SCHED_CORE_SHARE_TO   2
#define PR_SCHED_CORE_SHARE_FROM 3
#define PR_SCHED_CORE_MAX        4
#endif

/* Not defined in UAPI headers, but expected to be used with PR_SCHED_CORE */
#define PIDTYPE_PID  0
#define PIDTYPE_TGID 1
