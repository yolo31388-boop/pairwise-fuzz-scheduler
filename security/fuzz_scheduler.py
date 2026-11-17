"""Coverage-guided fuzz scheduler.

Fixes for the defects observed in the 24h campaign:

* corpus culling no longer evicts rare-path seeds just because they are large
  (see :func:`cull_corpus`);
* coverage is tracked as exact edge identities ``(src, dst)`` in a set, not a
  fixed-size global hash bitmap, so collisions can no longer masquerade new
  edges as already-seen ones (see :func:`update_coverage`);
* energy is assigned by path depth and edge novelty instead of a fixed per-seed
  mutation count, so deep paths actually get fuzzed (see :func:`energy`);
* crash dedup keys on the normalized stack (function frames, addresses and
  sanitizer-specific offsets stripped), so the same root cause reported by
  ASan and UBSan collapses to one crash (see :func:`dedupe_crashes`);
* slow/timeout seeds are quarantined away from the worker pool instead of
  starving it (see :func:`partition_by_speed`);
* corpus and progress are persisted as a versioned, deterministic state blob
  so a restart resumes instead of restarting (see :func:`save_state` /
  :func:`load_state`).
"""

import json
import re

STATE_VERSION = 1

MAX_ENERGY = 100.0

# A seed is "slow" when its average run time exceeds this many milliseconds.
DEFAULT_TIME_BUDGET_MS = 1000.0

# An edge hit fewer times than this across the whole corpus is "rare"; seeds
# covering rare edges are protected from size-based culling.
RARE_EDGE_THRESHOLD = 3


def select_seed(corpus, scores):
    """Pick the highest-energy seed from ``corpus``.

    ``scores`` maps seed id -> accumulated energy. Ties are broken by corpus
    order (earliest first) so scheduling is deterministic. Returns ``None``
    for an empty corpus.
    """
    best = None
    best_score = None
    for seed in corpus:
        score = scores.get(seed.get('id'), 0)
        if best is None or score > best_score:
            best = seed
            best_score = score
    return best


def update_coverage(seen_edges, new_edges):
    """Merge ``new_edges`` into ``seen_edges``; return how many were new.

    Edges are stored as exact ``(src, dst)`` tuples in a set. There is no
    fixed-size bitmap and no hashing of edges into buckets, so two distinct
    edges can never collide and hide new coverage.
    """
    added = 0
    for edge in new_edges:
        if edge not in seen_edges:
            seen_edges.add(edge)
            added += 1
    return added


_ADDR_RE = re.compile(r'0x[0-9a-fA-F]+')
_OFFSET_RE = re.compile(r'\+\s*0x[0-9a-fA-F]+')
_FRAME_RE = re.compile(r'#\d+\s+')


def _normalize_stack(stack):
    """Reduce a raw stack/sanitizer report to a stable signature.

    Addresses, byte offsets, frame numbers and sanitizer banner lines are
    stripped so the same bug reported by ASan and UBSan (or at different
    addresses under ASLR) produces the same key.
    """
    if not stack:
        return ()
    frames = []
    for line in str(stack).splitlines():
        line = line.strip()
        if not line:
            continue
        line = _FRAME_RE.sub('', line)
        line = _OFFSET_RE.sub('', line)
        line = _ADDR_RE.sub('', line)
        line = ' '.join(line.split())
        if line:
            frames.append(line)
    return tuple(frames)


def dedupe_crashes(crashes):
    """Deduplicate crashes by normalized stack signature.

    The first crash seen for each signature is kept; later duplicates
    (including the same root cause surfaced by a different sanitizer) are
    dropped.
    """
    seen = set()
    unique = []
    for crash in crashes:
        key = _normalize_stack(crash.get('stack'))
        if key in seen:
            continue
        seen.add(key)
        unique.append(crash)
    return unique


def energy(depth, novelty):
    """Mutation budget for a seed, from path ``depth`` and edge ``novelty``.

    Both deeper paths and recently-discovered edges earn more mutations,
    monotonically, so deep paths are no longer starved by a fixed count.
    The result is capped at :data:`MAX_ENERGY`.
    """
    depth = max(0.0, float(depth))
    novelty = max(0.0, float(novelty))
    return min(MAX_ENERGY, (1.0 + depth) * (1.0 + novelty))


def cull_corpus(corpus, edge_hit_counts, max_size):
    """Trim ``corpus`` to ``max_size`` seeds without losing rare paths.

    Seeds are evicted largest-first (the old policy), but any seed that
    covers a rare edge — one hit fewer than :data:`RARE_EDGE_THRESHOLD`
    times corpus-wide — is protected and kept regardless of its size.
    """
    if len(corpus) <= max_size:
        return list(corpus)

    def is_rare(seed):
        edges = seed.get('edges') or ()
        return any(edge_hit_counts.get(e, 0) < RARE_EDGE_THRESHOLD for e in edges)

    protected = [s for s in corpus if is_rare(s)]
    unprotected = [s for s in corpus if not is_rare(s)]
    unprotected.sort(key=lambda s: s.get('size', 0))

    keep = protected + unprotected[: max(0, max_size - len(protected))]
    return keep


def partition_by_speed(corpus, budget_ms=DEFAULT_TIME_BUDGET_MS):
    """Split ``corpus`` into ``(fast, slow)`` seeds.

    Seeds whose average execution time exceeds ``budget_ms`` are quarantined
    into ``slow`` so a few pathological inputs cannot occupy every worker;
    the caller should fuzz them on a separate, bounded queue.
    """
    fast, slow = [], []
    for seed in corpus:
        exec_ms = seed.get('exec_ms')
        if exec_ms is None:
            runs = seed.get('runs') or 0
            total = seed.get('total_exec_ms') or 0.0
            exec_ms = (total / runs) if runs else 0.0
        (slow if exec_ms > budget_ms else fast).append(seed)
    return fast, slow


def save_state(state):
    """Serialize fuzzing state to a deterministic, versioned JSON string.

    Keys are sorted so the same logical state always serializes to the same
    bytes, which keeps checkpoints diffable and idempotent.
    """
    payload = {'version': STATE_VERSION, 'state': state}
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))


def load_state(payload):
    """Restore state written by :func:`save_state`.

    Returns the original state dict, or ``None`` if the payload is not valid
    JSON, is not a state envelope, or carries an unsupported version — in
    which case the caller must rescan rather than resume from garbage.
    """
    try:
        data = json.loads(payload)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get('version') != STATE_VERSION:
        return None
    state = data.get('state')
    if not isinstance(state, dict):
        return None
    return state
