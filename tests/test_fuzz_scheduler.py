import pytest

from security.fuzz_scheduler import (
    select_seed,
    update_coverage,
    dedupe_crashes,
    energy,
    save_state,
    load_state
)


def test_select_max():
    assert select_seed([{'id': 'a'}, {'id': 'b'}], {'a': 3, 'b': 9})['id'] == 'b'

def test_select_empty():
    assert select_seed([], {}) is None

def test_select_tie():
    assert select_seed([{'id': 'a'}, {'id': 'b'}], {'a': 5, 'b': 5})['id'] == 'a'

def test_coverage_new():
    assert update_coverage(set(), {('a', 'b')}) == 1

def test_coverage_duplicate():
    assert update_coverage({('a', 'b')}, {('a', 'b')}) == 0

def test_coverage_multi():
    assert update_coverage(set(), {('a', 'b'), ('a', 'c')}) == 2

def test_crash_dedupe():
    assert len(dedupe_crashes([{'stack': 's1', 'id': 1}, {'stack': 's1', 'id': 2}])) == 1

def test_crash_distinct():
    assert len(dedupe_crashes([{'stack': 's1'}, {'stack': 's2'}])) == 2

def test_crash_empty():
    assert dedupe_crashes([]) == []

def test_energy_depth():
    assert energy(10, 0) > energy(2, 0)

def test_energy_novelty():
    assert energy(3, 5) > energy(3, 0)

def test_energy_cap():
    assert energy(100, 100) <= 100.0

def test_state_stable():
    assert save_state({'b': 2, 'a': 1}) == save_state({'a': 1, 'b': 2})

def test_state_roundtrip():
    assert load_state(save_state({'corpus': ['a'], 'crashes': []})) == {'corpus': ['a'], 'crashes': []}

def test_state_bad():
    assert load_state('{"version": 0}') is None
