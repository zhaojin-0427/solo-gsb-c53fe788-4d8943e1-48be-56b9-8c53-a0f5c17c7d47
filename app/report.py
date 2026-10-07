"""报告分页：从不可变 run 快照按页取字节，绝不物化缺口。"""

from __future__ import annotations

import base64

from . import db

DEFAULT_MAX_BYTES = 65536
HARD_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_RUNS = 2000
HARD_MAX_RUNS = 20000


def build_page(
    conn,
    session_id: str,
    direction: str,
    revision: int,
    offset: int,
    max_bytes: int,
    max_runs: int,
) -> dict | None:
    meta = db.get_revision_meta(conn, session_id, direction, revision)
    if meta is None:
        return None
    if offset < 1 or offset > (1 << 31):
        raise ValueError("offset 必须在 [1, 2^31] 内")

    # 只取与本页可能相交的 run（end>offset），多取一条判断 run 数是否超限
    rows = conn.execute(
        "SELECT idx, start_offset AS s, end_offset AS e,"
        " earliest_packet AS ep, earliest_capture AS ec,"
        " latest_packet AS lp, latest_capture AS lc, divergent AS d"
        " FROM runs WHERE session_id=? AND direction=? AND revision=?"
        " AND end_offset>? ORDER BY idx LIMIT ?",
        (session_id, direction, revision, offset, max_runs + 1),
    ).fetchall()

    truncated_by_run_limit = len(rows) > max_runs
    rows = rows[:max_runs]

    # 顺序消费 run，切成不超过 max_bytes 的字节块；单个 run 超长时按 run 内
    # 位置继续切，下一页从同一 run 的剩余部分接续。缺口不产生任何字节。
    chunks: list[tuple] = []  # (row, lo, hi)
    used_bytes = 0
    stopped_row = None
    stopped_at = offset
    for r in rows:
        lo = max(r["s"], offset)
        hi = r["e"]
        while lo < hi:
            take = min(hi - lo, max_bytes - used_bytes)
            chunks.append((r, lo, lo + take))
            used_bytes += take
            lo += take
            if used_bytes >= max_bytes:
                stopped_row = r
                stopped_at = lo
                break
        if stopped_row is not None:
            break

    if stopped_row is not None:
        more_after = stopped_at < stopped_row["e"] or any(
            r["idx"] > stopped_row["idx"] for r in rows
        )
    else:
        more_after = truncated_by_run_limit

    # 收集本页所需载荷片（packet_id + 逻辑区间），去重后读取
    refs: list[tuple[int, int, int]] = []
    ref_index: dict[tuple[int, int, int], int] = {}
    for r, lo, hi in chunks:
        for pid in (r["ep"], r["lp"]):
            key = (pid, lo, hi)
            if key not in ref_index:
                ref_index[key] = len(refs)
                refs.append(key)
    slices = db.payload_slices(conn, refs) if refs else []

    run_views = []
    earliest_parts: list[bytes] = []
    latest_parts: list[bytes] = []
    divergence: list[list[int]] = []

    for r, lo, hi in chunks:
        eb = slices[ref_index[(r["ep"], lo, hi)]]
        lb = slices[ref_index[(r["lp"], lo, hi)]]
        earliest_parts.append(eb)
        latest_parts.append(lb)

        # 本分块内部逐字节比较，产出分歧区间（绝对逻辑偏移，左闭右开）
        if eb != lb:
            i, n = 0, len(eb)
            while i < n:
                while i < n and eb[i] == lb[i]:
                    i += 1
                j = i
                while j < n and eb[j] != lb[j]:
                    j += 1
                if j > i:
                    divergence.append([lo + i, lo + j])
                i = j

        run_views.append({
            "index": r["idx"],
            "start": lo,
            "end": hi,
            "earliest_source": {
                "packet_id": r["ep"],
                "capture": r["ec"],
            },
            "latest_source": {
                "packet_id": r["lp"],
                "capture": r["lc"],
            },
            "divergent": bool(r["d"]),
        })

    earliest_bytes = b"".join(earliest_parts)
    latest_bytes = b"".join(latest_parts)
    earliest_b64 = base64.b64encode(earliest_bytes).decode("ascii")
    latest_b64 = base64.b64encode(latest_bytes).decode("ascii")

    next_offset = chunks[-1][2] if chunks and more_after else None

    return {
        "session_id": session_id,
        "direction": direction,
        "revision": meta["revision"],
        "isn": meta["isn"],
        "fin_pos": meta["fin_pos"],
        "complete": meta["complete"],
        "page": {
            "offset": offset,
            "returned_bytes": used_bytes,
            "run_count": len(chunks),
            "next_offset": next_offset,
            "done": next_offset is None,
        },
        "earliest_base64": earliest_b64,
        "latest_base64": latest_b64,
        "runs": run_views,
        "gaps": meta["gaps"],
        "divergence_intervals": divergence,
    }
