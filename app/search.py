"""字节特征定位：从指定修订的不可变 run 快照还原 earliest/latest 两份字节流，
对 Base64 模式做模式匹配，返回按逻辑偏移排序的命中起点与双侧命中类别。

关键语义：
* 数据源是修订发布时固化的 run（仅含逻辑区间与来源报文引用），载荷始终留在
  packets 表；旧修订的 run 不随后续发布变化，故旧修订命中永不变。
* 相邻 run（前一个 end == 下一个 start）共同构成连续字节，模式允许**跨 run 命中**；
  run 之间一旦存在缺口（下一个 start > 上一个 end）立即丢弃匹配状态，
  **绝不拼接缺口两端**。
* 逐窗口读取来源报文载荷（SQLite substr 窗口），KMP 匹配状态跨窗口/跨 run
  读取边界保持；允许重叠命中（如 "aa" 在 "aaa" 中命中 [1,3)、[2,4)）。
* earliest/latest 两侧分别扫描，同一起点归并为一条命中，类别为
  both / earliest_only / latest_only。
"""

from __future__ import annotations

import base64

from . import db

# 每次从单个 run 读取的载荷窗口：两侧各最多驻留 64 KiB，匹配状态跨窗口保持
READ_WINDOW = 65536
# 单批从 runs 表取出的 run 条数（顺序流式处理，不一次性载入整版快照）
BATCH_RUNS = 2000

CATEGORY_BOTH = "both"
CATEGORY_EARLIEST_ONLY = "earliest_only"
CATEGORY_LATEST_ONLY = "latest_only"


def kmp_failure(pattern: bytes) -> list[int]:
    """KMP 失配函数（前缀函数）。"""
    pi = [0] * len(pattern)
    k = 0
    for i in range(1, len(pattern)):
        while k and pattern[i] != pattern[k]:
            k = pi[k - 1]
        if pattern[i] == pattern[k]:
            k += 1
        pi[i] = k
    return pi


class KmpMatcher:
    """有状态 KMP：可连续喂入同一连续字节流的多个窗口/run。

    feed(chunk, base) 返回本块内确认的命中起点（逻辑偏移）。
    命中允许重叠：完全匹配后回退到最长真前后缀，而非清零。
    """

    __slots__ = ("pattern", "pi", "state")

    def __init__(self, pattern: bytes):
        self.pattern = pattern
        self.pi = kmp_failure(pattern)
        self.state = 0

    def reset(self) -> None:
        """遇到缺口时调用：缺口另一侧的字节不得与本侧共同构成匹配。"""
        self.state = 0

    def feed(self, chunk: bytes, base: int) -> list[int]:
        hits: list[int] = []
        pattern, pi, m = self.pattern, self.pi, len(self.pattern)
        state = self.state
        for i, ch in enumerate(chunk):
            while state and ch != pattern[state]:
                state = pi[state - 1]
            if ch == pattern[state]:
                state += 1
            if state == m:
                hits.append(base + i - m + 1)
                state = pi[state - 1]  # 允许重叠命中
        self.state = state
        return hits


def merge_same_offsets(
    earliest_hits: list[int], latest_hits: list[int]
) -> list[dict]:
    """两份各自按起点升序的命中流，按起点归并；同起点合并并标注双侧类别。"""
    i = j = 0
    ne, nl = len(earliest_hits), len(latest_hits)
    out: list[dict] = []
    while i < ne or j < nl:
        if j == nl or (i < ne and earliest_hits[i] < latest_hits[j]):
            out.append({"offset": earliest_hits[i], "category": CATEGORY_EARLIEST_ONLY})
            i += 1
        elif i == ne or (j < nl and latest_hits[j] < earliest_hits[i]):
            out.append({"offset": latest_hits[j], "category": CATEGORY_LATEST_ONLY})
            j += 1
        else:
            out.append({"offset": earliest_hits[i], "category": CATEGORY_BOTH})
            i += 1
            j += 1
    return out


def locate_pattern(
    conn,
    session_id: str,
    direction: str,
    revision: int,
    pattern: bytes,
    offset: int,
    limit: int,
) -> dict | None:
    """在指定修订的双份字节流上定位模式。

    修订不存在返回 None（路由层映射 404）。命中起点全部 >= offset；
    最多收集 limit+1 条以判定下一页，next_offset 为第 limit+1 条的起点，
    末页为 null。无命中返回空页。
    """
    meta = db.get_revision_meta(conn, session_id, direction, revision)
    if meta is None:
        return None

    earliest = KmpMatcher(pattern)
    latest = KmpMatcher(pattern)

    matches: list[dict] = []
    need = limit + 1
    cur_idx = 0
    prev_end: int | None = None  # 上一个已喂入 run 的末端（exclusive）

    while len(matches) < need:
        rows = db.iter_runs(
            conn,
            session_id,
            direction,
            revision,
            start_idx=cur_idx,
            min_end=offset,
            limit=BATCH_RUNS,
        )
        if not rows:
            break

        for r in rows:
            cur_idx = r["idx"] + 1
            run_lo, run_hi = max(r["s"], offset), r["e"]

            # run 与上一 run 不相邻（含 offset 落在缺口中的情形）=> 缺口截断
            if prev_end is not None and r["s"] > prev_end:
                earliest.reset()
                latest.reset()

            wlo = run_lo
            while wlo < run_hi and len(matches) < need:
                whi = min(wlo + READ_WINDOW, run_hi)
                refs = []
                ref_index: dict[tuple[int, int, int], int] = {}
                for pid in (r["ep"], r["lp"]):
                    key = (pid, wlo, whi)
                    if key not in ref_index:
                        ref_index[key] = len(refs)
                        refs.append(key)
                slices = db.payload_slices(conn, refs)
                eb = slices[ref_index[(r["ep"], wlo, whi)]]
                lb = slices[ref_index[(r["lp"], wlo, whi)]]

                # 同一逻辑窗口内两侧命中对齐，同起点可在此直接归并；
                # 跨窗口的命中起点严格递增（见模块说明），可顺序追加。
                e_hits = earliest.feed(eb, wlo)
                l_hits = latest.feed(lb, wlo)
                if e_hits or l_hits:
                    matches.extend(merge_same_offsets(e_hits, l_hits))
                wlo = whi

            prev_end = r["e"]
            if len(matches) >= need:
                break

    page_hits = matches[:limit]
    next_offset = matches[limit]["offset"] if len(matches) > limit else None
    return {
        "session_id": session_id,
        "direction": direction,
        "revision": meta["revision"],
        "pattern_base64": base64.b64encode(pattern).decode("ascii"),
        "offset": offset,
        "limit": limit,
        "hits": page_hits,
        "next_offset": next_offset,
        "done": next_offset is None,
    }
