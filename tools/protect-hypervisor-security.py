#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Exercise protected-task VMA permissions, segfaults with ProtectHypervisor=yes"""

import argparse
import ctypes
import errno
import mmap
import os
import platform
import resource
import signal


# PML4 + 256 PUDs + 4 hole-edge tables + syscall stub
PROTECTED_IMAGE_SIZE = 262 * mmap.PAGESIZE
HUGETLB_SIZE = 2 * 1024 * 1024

MAP_HUGETLB = 0x40000
MAP_HUGE_SHIFT = 26
MAP_HUGE_2MB = 21 << MAP_HUGE_SHIFT

IO_URING_SETUP = 425
IO_URING_REGISTER = 427
IORING_REGISTER_BUFFERS = 0

PR_SET_MDWE = 65
PR_MDWE_REFUSE_EXEC_GAIN = 1 << 0
MAP_FIXED_NOREPLACE = 0x100000
DEVICE_TARGET_ADDRESS = 0x700000000000

LEGACY_CHARACTER_DEVICES = (
    "/dev/fb0",
    "/dev/snd/pcmC0D0p",
    "/dev/snd/pcmC0D0c",
    "/dev/dri/card0",
    "/dev/dri/renderD128",
    "/dev/hpet",
    "/dev/uio0",
    "/dev/video0",
)


class IoSqringOffsets(ctypes.Structure):
    _fields_ = [
        ("head", ctypes.c_uint32),
        ("tail", ctypes.c_uint32),
        ("ring_mask", ctypes.c_uint32),
        ("ring_entries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("dropped", ctypes.c_uint32),
        ("array", ctypes.c_uint32),
        ("resv1", ctypes.c_uint32),
        ("user_addr", ctypes.c_uint64),
    ]


class IoCqringOffsets(ctypes.Structure):
    _fields_ = [
        ("head", ctypes.c_uint32),
        ("tail", ctypes.c_uint32),
        ("ring_mask", ctypes.c_uint32),
        ("ring_entries", ctypes.c_uint32),
        ("overflow", ctypes.c_uint32),
        ("cqes", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("resv1", ctypes.c_uint32),
        ("user_addr", ctypes.c_uint64),
    ]


class IoUringParams(ctypes.Structure):
    _fields_ = [
        ("sq_entries", ctypes.c_uint32),
        ("cq_entries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("sq_thread_cpu", ctypes.c_uint32),
        ("sq_thread_idle", ctypes.c_uint32),
        ("features", ctypes.c_uint32),
        ("wq_fd", ctypes.c_uint32),
        ("resv", ctypes.c_uint32 * 3),
        ("sq_off", IoSqringOffsets),
        ("cq_off", IoCqringOffsets),
    ]


class Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]

libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_long,
]
libc.mmap.restype = ctypes.c_void_p
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.mprotect.restype = ctypes.c_int
libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
libc.prctl.restype = ctypes.c_int
libc.syscall.restype = ctypes.c_long


def map_memory(protection, flags, fd=-1, size=mmap.PAGESIZE):
    address = libc.mmap(None, size, protection, flags, fd, 0)
    if address == ctypes.c_void_p(-1).value:
        os._exit(1)
    return address


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--uring",
        action="store_true",
        help="run the hugetlb io_uring fixed-buffer fork reproducer",
    )
    mode.add_argument(
        "--device",
        action="store_true",
        help="run the legacy character-device MDWE mmap reproducer",
    )
    return parser.parse_args()


def run_uring():
    if platform.machine() != "x86_64" or ctypes.sizeof(IoUringParams) != 120:
        return 1

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    memory = map_memory(
        mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB,
        size=HUGETLB_SIZE,
    )
    ctypes.memset(memory, 0, HUGETLB_SIZE)

    params = IoUringParams()
    ring_fd = libc.syscall(IO_URING_SETUP, 1, ctypes.byref(params))
    if ring_fd < 0:
        return 1

    try:
        iov = Iovec(memory, HUGETLB_SIZE)
        if libc.syscall(
            IO_URING_REGISTER,
            ring_fd,
            IORING_REGISTER_BUFFERS,
            ctypes.byref(iov),
            1,
        ) < 0:
            return 1

        if libc.mprotect(memory, HUGETLB_SIZE, mmap.PROT_READ) < 0:
            return 1

        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGSEGV, signal.SIG_DFL)
            ctypes.memset(memory, 1, HUGETLB_SIZE)
            os._exit(1)

        waited, status = os.waitpid(child, 0)
        return int(
            waited != child
            or not os.WIFSIGNALED(status)
            or os.WTERMSIG(status) != signal.SIGSEGV
        )
    finally:
        os.close(ring_fd)


def run_device():
    device_fd = -1
    for path in LEGACY_CHARACTER_DEVICES:
        try:
            device_fd = os.open(path, os.O_RDWR)
            break
        except OSError:
            pass

    if device_fd < 0:
        return 1

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        if libc.prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) < 0:
            return 1

        ctypes.set_errno(0)
        address = libc.mmap(
            DEVICE_TARGET_ADDRESS,
            mmap.PAGESIZE,
            mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
            mmap.MAP_SHARED | MAP_FIXED_NOREPLACE,
            device_fd,
            0,
        )
        if (
            address == ctypes.c_void_p(-1).value
            and ctypes.get_errno() == errno.EACCES
        ):
            ctypes.c_ubyte.from_address(DEVICE_TARGET_ADDRESS).value
            return 1

        return 0
    finally:
        os.close(device_fd)


def find_protected_image():
    # Find the sealed PROT_NONE VMA holding the protected task's page tables.
    matches = []
    with open("/proc/self/maps", encoding="ascii") as maps:
        for line in maps:
            fields = line.split()
            start, end = (int(value, 16) for value in fields[0].split("-"))
            if (
                end - start == PROTECTED_IMAGE_SIZE
                and len(fields) == 5
                and fields[1] == "---p"
                and fields[4] == "0"
            ):
                matches.append(start)
    return matches


def run_permissions():
    protected_images = find_protected_image()
    if not protected_images:
        return 0
    if len(protected_images) != 1 or platform.machine() != "x86_64":
        return 1

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    memfd = os.memfd_create("protect-hypervisor-security", os.MFD_CLOEXEC)
    os.ftruncate(memfd, mmap.PAGESIZE)
    if os.pwrite(memfd, b"A", 0) != 1:
        return 1

    read_only = map_memory(mmap.PROT_READ, mmap.MAP_SHARED, memfd)
    read_write = map_memory(
        mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
    )
    ctypes.memmove(read_write, b"\xc3", 1)

    child = os.fork()
    if child == 0:
        ctypes.CFUNCTYPE(None)(read_write)()
        os._exit(1)

    waited, status = os.waitpid(child, 0)
    if (
        waited != child
        or not os.WIFSIGNALED(status)
        or os.WTERMSIG(status) != signal.SIGSEGV
    ):
        return 1

    read_only_cell = ctypes.c_ubyte.from_address(read_only)
    if read_only_cell.value != ord("A"):
        return 1
    if os.pwrite(memfd, b"K", 0) != 1 or read_only_cell.value != ord("K"):
        return 1

    # EPT/NPT rejects this write despite the writable first-stage PTE.
    read_only_cell.value = ord("B")
    return 1


def main():
    arguments = parse_arguments()
    if arguments.uring:
        return run_uring()
    if arguments.device:
        return run_device()
    return run_permissions()


if __name__ == "__main__":
    try:
        os._exit(main())
    except BaseException:
        os._exit(1)
