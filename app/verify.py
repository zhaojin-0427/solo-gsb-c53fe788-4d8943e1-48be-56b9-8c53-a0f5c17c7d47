"""对端确认缺口核验。

目标：某方向的**指定修订**（以该修订冻结的 SYN 锚 ISN 与缺口为准），把
**请求时已入库的反向报文**中的 32 位 ACK / SACK 换算为逻辑偏移，与修订缺口求交：

* ``acknowledged_gaps`` —— 已被对端确认、但本侧未捕获的区间（已确认但未捕获）；
* ``unacknowledged_gaps`` —— 缺口内没有任何确认依据的区间（无确认依据）。

关键语义：

* 累计 ACK 覆盖 ``[1, cum)``，**SACK 块只覆盖各自区间**，绝不能把 SACK 上界
  当作累计确认；重复 / 倒序 ACK、重叠 SACK 经并集运算天然不重复计数。
* 半序号窗口：相对偏移落在 ``[0, 2^31]`` 之外的确认一律忽略
  （SACK 块越窗部分裁掉，整块回绕则丢弃）；窗口外报文计入
  ``ignored_outside_window``。
* 确认集合在请求时重算：晚到的 ACK/SACK 证据会立即更新核验结果，
  而修订的 run / 缺口 / 报告 / 定位全部随修订冻结、保持不变。
* ``unacknowledged_gaps`` 只代表“没有确认依据”，**不等于数据未送达**。
"""

from __future__ import annotations

from . import db
from .reassembly import LIMIT, MOD, relative_offset

NOTE = (
    "unacknowledged_gaps 仅表示缺口缺少确认依据，不等于未送达；"
    "确认集合按请求时已入库的反向报文重算，晚到证据会更新本核验，"
    "修订报告与定位不随之变化"
)


def _intersect(intervals, lo: int, hi: int) -> list[list[int]]:
    """区间列表与 [lo,hi) 的交集，保持升序、不合并。"""
    out: list[list[int]] = []
    for a, b in intervals:
        x, y = max(a, lo), min(b, hi)
        if y > x:
            out.append([x, y])
    return out


def _subtract_unit(intervals, lo: int, hi: int) -> list[list[int]]:
    """从有序不相交区间列表中减去 [lo,hi)。"""
    out: list[list[int]] = []
    for a, b in intervals:
        x, y = max(a, lo), min(b, hi)
        if y <= x:
            out.append([a, b])
            continue
        if a < x:
            out.append([a, x])
        if y < b:
            out.append([y, b])
    return out


def _subtract_all(intervals, covers) -> list[list[int]]:
    for lo, hi in covers:
        intervals = _subtract_unit(intervals, lo, hi)
    return intervals


def build_verification(
    conn,
    session_id: str,
    direction: str,
    revision: int,
) -> dict | None:
    """生成对端确认缺口核验；修订不存在返回 None（上层映射 404）。"""
    meta = db.get_revision_meta(conn, session_id, direction, revision)
    if meta is None:
        return None

    isn = meta["isn"]
    gaps = [list(g) for g in meta["gaps"]]

    # 反向报文即对端确认证据（ACK 由对端填入）
    peer_direction = "s2c" if direction == "c2s" else "c2s"
    import json

    rows = conn.execute(
        "SELECT id, capture, ack, sack FROM packets"
        " WHERE session_id=? AND direction=? ORDER BY id",
        (session_id, peer_direction),
    ).fetchall()

    ignored_outside_window = 0

    # ---- 累计 ACK：窗口内最大确认偏移；并列取最晚捕获 ----
    cum = 0
    cum_source: dict | None = None
    # ---- SACK：保留落在窗口内的原始块（裁剪后）及其来源 ----
    raw_sack: list[tuple[int, int, dict]] = []

    for r in rows:
        if r["ack"] is None:
            continue  # 旧格式报文，无确认字段
        rel = relative_offset(r["ack"], isn)
        blocks = json.loads(r["sack"] or "[]")

        evidence = {"packet_id": r["id"], "capture": r["capture"], "ack": r["ack"]}

        # 半序号窗口：ACK 本身越窗，整条确认证据（含其 SACK）忽略
        if rel > LIMIT:
            ignored_outside_window += 1
            continue

        if rel > cum or (rel == cum and rel > 0 and
                         (cum_source is None or r["capture"] > cum_source["capture"])):
            cum = rel
            cum_source = evidence

        # SACK 块各自换算；相对回绕（left>=right）或整块越窗则丢弃，
        # 部分越窗只保留 [.., 2^31] 内的部分。
        for l32, r32 in blocks:
            lo = relative_offset(l32, isn)
            hi = relative_offset(r32, isn)
            if lo >= hi:
                ignored_outside_window += 1
                continue
            if lo >= LIMIT:
                ignored_outside_window += 1
                continue
            hi = min(hi, LIMIT)
            if hi <= 0:
                ignored_outside_window += 1
                continue
            raw_sack.append((lo, hi, evidence))

    # ---- 合并重叠/相邻 SACK 块，收集各合并块的来源 ----
    raw_sack.sort(key=lambda t: (t[0], -t[1]))
    merged: list[dict] = []
    for lo, hi, ev in raw_sack:
        if merged and lo <= merged[-1]["end"]:
            if hi > merged[-1]["end"]:
                merged[-1]["end"] = hi
            merged[-1]["_sources"].add(ev["packet_id"])
            merged[-1]["_ev_by_id"][ev["packet_id"]] = ev
        else:
            merged.append({
                "start": lo,
                "end": hi,
                "_sources": {ev["packet_id"]},
                "_ev_by_id": {ev["packet_id"]: ev},
            })

    # 确认覆盖（与缺口求交前）：累计 ACK = [1,cum)；SACK 各块独立。
    # 对外只展示超出累计 ACK 的 SACK 部分；与累计重叠的部分不重复计为 SACK，
    # 但 SACK 上界绝不抬升 cum。
    ack_cover: list[tuple[int, int]] = []
    if cum > 1:
        ack_cover.append((1, cum))

    sack_views: list[dict] = []
    for m in merged:
        s = max(m["start"], 1, cum)
        e = m["end"]
        sources = [
            m["_ev_by_id"][pid]
            for pid in sorted(m["_ev_by_id"], key=lambda p: m["_ev_by_id"][p]["capture"])
        ]
        if e > s:
            sack_views.append({"start": s, "end": e, "sources": sources})
            ack_cover.append((s, e))

    # ---- 与修订缺口求交：已确认但未捕获 / 无确认依据 ----
    acknowledged: list[list[int]] = []
    for lo, hi in ack_cover:
        acknowledged.extend(_intersect(gaps, lo, hi))
    acknowledged.sort()

    unacknowledged = _subtract_all([list(g) for g in gaps], ack_cover)

    return {
        "session_id": session_id,
        "direction": direction,
        "revision": revision,
        "isn": isn,
        "fin_pos": meta["fin_pos"],
        "gaps": gaps,
        "cumulative_ack": {"offset": cum, "source": cum_source},
        "sack_blocks": sack_views,
        "acknowledged_gaps": acknowledged,
        "unacknowledged_gaps": unacknowledged,
        "ignored_outside_window": ignored_outside_window,
        "note": NOTE,
    }
