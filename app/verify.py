"""对端确认缺口核验：用反方向报文里的 ACK / SACK 证据核验修订冻结的缺口。

语义（核验方向 = 数据方向，证据方向 = 其对端方向）：

* 缺口取自**指定修订**发布时冻结的 `gaps`（随修订不可变；纯 SYN/FIN 无载荷时
  缺口自然只覆盖 FIN 之前的范围）；确认集合在**请求时**按当前已入库的反向
  报文重算，因此晚到的 ACK/SACK 证据会反映在下一次核验结果里。
* 换算锚点是**目标修订的 ISN**（该方向唯一 SYN 的 32 位 seq）：
    - 累计 ACK：确认偏移 `ack_off = (ack - isn) mod 2^32`，覆盖 `[1, ack_off)`；
      仅当 `1 < ack_off <= 2^31` 时有效（`ack_off` 落在半序号窗口外的一律忽略）。
    - SACK 半开块 `[l, r)`：换算为 `[rel(l), rel(r))`，**只覆盖各块本身**，
      绝不把块上界当作累计确认；块越出半序号窗口（`rel(l) >= rel(r)` 或
      `rel(r) > 2^31`）时整块忽略。
* 重复或倒序的 ACK、相互重叠的 SACK 块**不重复计数**：所有确认区间先取并集，
  再与缺口相交。
* 结果把每个缺口划分为：
    - `acknowledged_but_missing`：已被对端确认、但本方向未捕获到字节的区间；
    - `no_evidence`：没有任何确认依据的区间（**不等于未送达**，只是无证据）。
"""

from __future__ import annotations

import json

from . import db
from .reassembly import LIMIT, MOD

PEER_DIRECTION = {"c2s": "s2c", "s2c": "c2s"}


def merge_intervals(intervals) -> list[list[int]]:
    """区间并集：重叠或首尾相接的区间合并，重复/倒序输入不重复计数。"""
    out: list[list[int]] = []
    for s, e in sorted(intervals):
        if s >= e:
            continue
        if out and s <= out[-1][1]:
            if e > out[-1][1]:
                out[-1][1] = e
        else:
            out.append([s, e])
    return out


def intersect_intervals(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    """两个已排序、互不重叠的区间列表的交集。"""
    out: list[list[int]] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo < hi:
            out.append([lo, hi])
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def subtract_intervals(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    """a − b：从已排序不重叠的 a 中扣除已排序不重叠的 b。"""
    out: list[list[int]] = []
    for g0, g1 in a:
        cur = g0
        for c0, c1 in b:
            if c1 <= cur:
                continue
            if c0 >= g1:
                break
            if c0 > cur:
                out.append([cur, min(c0, g1)])
            cur = max(cur, c1)
            if cur >= g1:
                break
        if cur < g1:
            out.append([cur, g1])
    return out


def _ack_coverage(ack: int, isn: int) -> tuple[int, int] | None:
    """累计 ACK 换算为覆盖区间 [1, ack_off)；半序号窗口外返回 None。"""
    ack_off = (ack - isn) % MOD
    if not 1 < ack_off <= LIMIT:
        return None
    return (1, ack_off)


def _sack_coverage(left: int, right: int, isn: int) -> tuple[int, int] | None:
    """SACK 半开块换算为覆盖区间；只覆盖块本身，窗口外返回 None。"""
    rel_l = (left - isn) % MOD
    rel_r = (right - isn) % MOD
    if rel_l >= rel_r or rel_r > LIMIT:
        return None
    start = max(rel_l, 1)  # 偏移 0 是 SYN，不是数据字节
    if start >= rel_r:
        return None
    return (start, rel_r)


def verify_gaps(
    conn,
    session_id: str,
    direction: str,
    revision: int,
) -> dict | None:
    """核验指定修订的缺口。修订不存在返回 None（路由层映射 404）。

    确认集合按请求时刻已入库的反方向报文实时重算；返回的
    `acknowledged_but_missing` 与 `no_evidence` 构成修订缺口的划分。
    """
    meta = db.get_revision_meta(conn, session_id, direction, revision)
    if meta is None:
        return None
    isn = meta["isn"]
    peer = PEER_DIRECTION[direction]

    evidence: list[dict] = []
    for row in db.iter_ack_packets(conn, session_id, peer):
        if row["ack"] is not None:
            cov = _ack_coverage(row["ack"], isn)
            if cov is not None:
                evidence.append({
                    "kind": "ack",
                    "start": cov[0],
                    "end": cov[1],
                    "packet_id": row["id"],
                    "capture": row["capture"],
                })
        if row["sack"]:
            for left, right in json.loads(row["sack"]):
                cov = _sack_coverage(left, right, isn)
                if cov is not None:
                    evidence.append({
                        "kind": "sack",
                        "start": cov[0],
                        "end": cov[1],
                        "packet_id": row["id"],
                        "capture": row["capture"],
                    })

    coverage = merge_intervals([(e["start"], e["end"]) for e in evidence])
    gaps = [list(g) for g in meta["gaps"]]
    acknowledged = intersect_intervals(gaps, coverage)
    no_evidence = subtract_intervals(gaps, coverage)
    evidence.sort(key=lambda e: (e["start"], e["end"], e["capture"]))

    return {
        "session_id": session_id,
        "direction": direction,
        "revision": meta["revision"],
        "isn": isn,
        "fin_pos": meta["fin_pos"],
        "complete": meta["complete"],
        "evidence_direction": peer,
        "gaps": gaps,
        "acknowledged_but_missing": acknowledged,
        "no_evidence": no_evidence,
        "evidence": evidence,
    }
