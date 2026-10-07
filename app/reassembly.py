"""TCP 会话重组的纯函数核心：相对序号、发布校验、扫描线裁决。

约定（每个 (session, direction) 一条独立字节流）：

* SYN 占用逻辑偏移 0（SYN 本身不带数据），其 32 位 seq 为 ISN。
* 数据字节的逻辑偏移 = (seq - isn) mod 2^32，合法范围为 1 .. 2^31-1；
  字节末端 rel_end 最大为 2^31。偏移达到/超过 2^31 的载荷拒绝发布。
* FIN 占用 FIN 序号之后的一个位置 fin_pos（1..2^31）。FIN 位置冲突、
  FIN 之后仍出现数据字节，均拒绝发布。
* 重叠加载按捕获序号(capture)裁决：
    earliest —— 重叠区由最早捕获（capture 最小）的报文持有；
    latest   —— 重叠区由最晚捕获（capture 最大）的报文持有。
"""

from __future__ import annotations

from dataclasses import dataclass

MOD = 1 << 32
LIMIT = 1 << 31  # 合法字节末端的最大值；首个不允许出现的逻辑偏移


def relative_offset(seq: int, isn: int) -> int:
    """32 位回绕的相对偏移，结果落在 [0, 2^32)。"""
    return (seq - isn) % MOD


class PublishRejected(Exception):
    """当前数据无法锚定/违反发布规则（422）。"""


class RevisionConflict(Exception):
    """期望修订号与当前修订号不一致，或同捕获序号异内容（409）。

    current_revision 为服务器当前修订号（无修订时为 0）。
    """

    def __init__(self, current_revision: int, message: str):
        super().__init__(message)
        self.current_revision = current_revision
        self.message = message


@dataclass(frozen=True)
class Segment:
    """一版快照内、一条报文贡献的字节区间（已按 ISN 换算为逻辑偏移）。"""

    packet_id: int
    capture: int
    start: int  # inclusive, 数据字节不存在时 start == end
    end: int  # exclusive

    def __len__(self) -> int:
        return self.end - self.start


@dataclass
class DirectionSnapshot:
    """发布前从数据库读出的整条方向原始视图。"""

    isn: int | None
    syn_packets: list[tuple]  # (packet_id, capture, seq)
    fin_pos: int | None
    fin_packets: list[tuple[int, int, int]]  # (packet_id, capture, seq)
    segments: list[Segment]  # 全部带数据报文


def validate_and_resolve(snap: DirectionSnapshot) -> tuple[int, int | None, list[Segment]]:
    """按发布规则校验快照，返回 (isn, fin_pos, 合法 Segment 列表)。

    抛出 PublishRejected / RevisionConflict 由上层映射为 HTTP 状态码。
    """
    if len(snap.syn_packets) != 1:
        if not snap.syn_packets:
            raise PublishRejected("方向缺少唯一 SYN，无法锚定序列号")
        raise PublishRejected(
            f"方向存在 {len(snap.syn_packets)} 个 SYN（不同 seq），唯一 SYN 锚点不成立"
        )

    isn = snap.isn
    assert isn is not None

    fin_pos = snap.fin_pos
    resolved: list[Segment] = []
    for seg in snap.segments:
        if seg.start >= LIMIT:
            raise PublishRejected(
                f"报文 capture={seg.capture} 的起始偏移 {seg.start} 已达到 2^31，拒绝发布"
            )
        if seg.end > LIMIT:
            raise PublishRejected(
                f"报文 capture={seg.capture} 的末端偏移 {seg.end} 越过 2^31，拒绝发布"
            )
        if fin_pos is not None and seg.end > fin_pos:
            raise PublishRejected(
                f"报文 capture={seg.capture} 的数据越过 FIN 位置 {fin_pos}（FIN 后出现新字节）"
            )
        if len(seg) > 0:
            resolved.append(seg)

    return isn, fin_pos, resolved


# ---- 扫描线：把重叠区间裁成“原子行程(run)”，分别按 earliest / latest 裁决 ----


def sweep_segments(segments: list[Segment]):
    """生成 (run_start, run_end, earliest_seg, latest_seg) 原子行程。

    事件流：段起点（入集合）与段终点（出集合）按位置合并；
    同一位置先处理“终点”再处理“起点”，相邻段不会产出零长度行程。
    活动集合中的最早/最晚捕获报文分别用最小/最大堆惰性维护。
    """
    import heapq

    starts = sorted(segments, key=lambda s: s.start)
    ends = sorted(segments, key=lambda s: s.end)
    si = ei = 0
    n = len(segments)

    active: set[int] = set()  # packet_id
    seg_by_id: dict[int, Segment] = {}
    min_heap: list[tuple[int, int]] = []  # (capture, packet_id)
    max_heap: list[tuple[int, int]] = []  # (-capture, packet_id)

    def heaps_clean() -> None:
        while min_heap and min_heap[0][1] not in active:
            heapq.heappop(min_heap)
        while max_heap and max_heap[0][1] not in active:
            heapq.heappop(max_heap)

    pos = None
    while ei < n or si < n:
        next_end = ends[ei].end if ei < n else None
        next_start = starts[si].start if si < n else None
        nxt: int
        if next_end is None:
            nxt = next_start  # type: ignore[assignment]
        elif next_start is None:
            nxt = next_end
        else:
            nxt = min(next_end, next_start)

        if pos is not None and active and nxt > pos:
            heaps_clean()
            e_seg = seg_by_id[min_heap[0][1]]
            l_seg = seg_by_id[max_heap[0][1]]
            yield pos, nxt, e_seg, l_seg

        # 同位置先移出终点段
        while ei < n and ends[ei].end == nxt:
            active.discard(ends[ei].packet_id)
            ei += 1
        # 再加入起点段
        while si < n and starts[si].start == nxt:
            seg = starts[si]
            seg_by_id[seg.packet_id] = seg
            active.add(seg.packet_id)
            heapq.heappush(min_heap, (seg.capture, seg.packet_id))
            heapq.heappush(max_heap, (-seg.capture, seg.packet_id))
            si += 1
        pos = nxt


def merge_runs(atomic):
    """把相邻、且 earliest/latest 归属都相同的原子行程合并为对外 run。

    输出 dict：start,end,earliest_packet,earliest_capture,
              latest_packet,latest_capture,divergent
    """
    cur: dict | None = None
    for start, end, e_seg, l_seg in atomic:
        if (
            cur is not None
            and start == cur["end"]
            and e_seg.packet_id == cur["earliest_packet"]
            and l_seg.packet_id == cur["latest_packet"]
        ):
            cur["end"] = end
            continue
        if cur is not None:
            yield cur
        cur = {
            "start": start,
            "end": end,
            "earliest_packet": e_seg.packet_id,
            "earliest_capture": e_seg.capture,
            "latest_packet": l_seg.packet_id,
            "latest_capture": l_seg.capture,
            "divergent": e_seg.packet_id != l_seg.packet_id,
        }
    if cur is not None:
        yield cur


def runs_complete(runs: list[dict], fin_pos: int | None) -> bool:
    """有 FIN 且 FIN 之前 [1, fin_pos) 全覆盖且无缺口，才算完整。"""
    if fin_pos is None:
        return False
    covered = 0
    for r in runs:
        lo = max(r["start"], 1)
        hi = min(r["end"], fin_pos)
        if hi > lo:
            covered += hi - lo
    return covered == fin_pos - 1


def gap_intervals(runs: list[dict], fin_pos: int | None):
    """缺口区间。FIN 存在时只报告 FIN 之前；否则报告已覆盖跨度内的缺口。"""
    if not runs:
        return []
    data_runs = [r for r in runs if r["end"] > 1]
    if not data_runs:
        return []
    horizon = fin_pos if fin_pos is not None else max(r["end"] for r in runs)
    gaps: list[list[int]] = []
    cursor = 1
    for r in runs:
        lo, hi = max(r["start"], 1), min(r["end"], horizon)
        if hi <= 1 or lo >= horizon:
            continue
        if lo > cursor:
            gaps.append([cursor, lo])
        cursor = max(cursor, hi)
    if cursor < horizon:
        gaps.append([cursor, horizon])
    return gaps
