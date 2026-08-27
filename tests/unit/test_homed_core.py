from __future__ import annotations

import errno
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from astral_project.homed.core import (
    ROOT_INODE,
    EmptyProjectedHome,
    FileHandleTable,
    HomedError,
    InodeRecord,
    InodeTable,
    RequestBudget,
    RequestLease,
)


def test_empty_home_only_exposes_root_and_forget_is_safe() -> None:
    state = EmptyProjectedHome()
    assert state.getattr(ROOT_INODE).inode == ROOT_INODE
    assert state.lookup(ROOT_INODE, b".").inode == ROOT_INODE
    state.forget(ROOT_INODE, 100)
    assert state.inodes.lookup_count(ROOT_INODE) == 0
    with pytest.raises(HomedError) as error:
        state.lookup(ROOT_INODE, b"secret")
    assert error.value.errno == errno.ENOENT


def test_concurrent_lookup_does_not_corrupt_inode_table() -> None:
    state = EmptyProjectedHome()
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: state.lookup(ROOT_INODE, b"."), range(200)))
    assert all(result.inode == ROOT_INODE for result in results)
    assert state.inodes.lookup_count(ROOT_INODE) == 201


def test_empty_home_rejects_handles_and_writes() -> None:
    state = EmptyProjectedHome()
    with pytest.raises(HomedError) as error:
        state.lookup(2, b".")
    assert error.value.errno == errno.ENOENT
    with pytest.raises(HomedError) as error:
        state.open(ROOT_INODE, os.O_RDONLY)
    assert error.value.errno == errno.EISDIR
    state.inodes._records[2] = InodeRecord(2, 0o100644)  # test-only synthetic file
    with pytest.raises(HomedError) as error:
        state.open(2, os.O_WRONLY)
    assert error.value.errno == errno.EROFS
    handle = state.open(2, os.O_RDONLY)
    state.release(handle)


def test_closed_home_is_unusable_and_handles_release() -> None:
    state = EmptyProjectedHome()
    state.close()
    with pytest.raises(HomedError) as error:
        state.getattr(ROOT_INODE)
    assert error.value.errno == errno.ESTALE


def test_inode_and_handle_tables_reject_unknowns_and_release() -> None:
    table = InodeTable()
    with pytest.raises(HomedError):
        table.getattr(99)
    with pytest.raises(HomedError):
        table.lookup_root(b"child")
    table.forget(99, -1)
    table.forget(99, 1)
    table._records[2] = InodeRecord(2, 0o100644)
    table._lookups[2] = 1
    table.forget(2, 1)
    assert 2 not in table._records
    handles = FileHandleTable()
    with pytest.raises(HomedError) as error:
        handles.allocate(ROOT_INODE)
    assert error.value.errno == errno.EISDIR
    handle = handles.allocate(2)
    assert handles.contains(handle)
    handles.release(handle)
    assert not handles.contains(handle)
    handles.release(99)
    handles.close_all()


def test_request_budget_bounds_queue_and_memory() -> None:
    with pytest.raises(ValueError):
        RequestBudget(max_requests=0)
    with pytest.raises(ValueError):
        RequestBudget(max_memory=0)
    budget = RequestBudget(max_requests=2, max_memory=4)
    with pytest.raises(HomedError) as error:
        budget.reserve(5)
    assert error.value.errno == errno.ENOMEM
    budget.reserve(4)
    with pytest.raises(HomedError) as error:
        budget.reserve(1)
    assert error.value.errno == errno.ENOMEM
    budget.release(4)
    budget.reserve(1)
    budget.release(99)
    assert budget.memory_used == 0
    queue = RequestBudget(max_requests=1, max_memory=4)
    with RequestLease(queue, 1) as lease:
        lease.cancel()
        lease.cancel()
    assert queue.memory_used == 0
    queue.reserve(1)
    with pytest.raises(HomedError) as error:
        queue.reserve(1)
    assert error.value.errno == errno.EAGAIN
    budget.release(4)
    budget.reserve(2)
    assert budget.memory_used == 2
    budget.release(2)
