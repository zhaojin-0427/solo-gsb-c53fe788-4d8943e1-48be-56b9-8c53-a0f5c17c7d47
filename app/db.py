"""SQLite 持久层：报文原始存储、修订快照、扫描线结果 run。

设计要点：
* 报文上传时只做原始入库（含内容哈希，用于同捕获序号异内容冲突），
  不依赖 SYN 是否已到达 —— 上传顺序不影响结果。
* 发布时在单事务内锚定 ISN、校验全部规则、重算 run，写入不可变快照。
* 大缺口（近 2^31）不占任何字节：缺口只表现为 run 之间的整数区间，
  报告接口按 run 分页，不补零、不物化缺口。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager

from .reassembly import (
    LIMIT,
    MOD,
    DirectionSnapshot,
    PublishRejected,
    RevisionConflict,
    Segment,
    gap_intervals,
    merge_runs,
    relative_offset,
    runs_complete,
    sweep_segments,
    validate_and_resolve,
)

VALID_DIRECTIONS = ("c2s", "s2c")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    direction   TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
    capture     INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    syn         INTEGER NOT NULL,
    fin         INTEGER NOT NULL,
    payload     BLOB NOT NULL,
    ack         INTEGER,               -- 32 位确认号；NULL 表示报文不带 ACK
    sack        TEXT,                  -- JSON [[l,r],...] 半开块；NULL 表示无 SACK
    sha256      TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(session_id, direction, capture)
);

CREATE INDEX IF NOT EXISTS idx_packets_stream
    ON packets(session_id, direction, id);

-- 每次成功发布产生一行修订（修订内容不可变）。
-- revision 号按 (会话, 方向) 独立从 1 递增。
CREATE TABLE IF NOT EXISTS revisions (
    revision    INTEGER NOT NULL,          -- 该方向内的修订号
    session_id  TEXT NOT NULL,
    direction   TEXT NOT NULL,
    isn         INTEGER NOT NULL,
    fin_pos     INTEGER,                 -- NULL 表示未见 FIN
    complete    INTEGER NOT NULL,
    run_count   INTEGER NOT NULL,
    gaps        TEXT NOT NULL,           -- JSON [[start,end],...]
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (session_id, direction, revision)
);

-- 原子行程快照：载荷仍保存在 packets 中，run 只引用来源
CREATE TABLE IF NOT EXISTS runs (
    session_id       TEXT NOT NULL,
    direction        TEXT NOT NULL,
    revision         INTEGER NOT NULL,
    idx              INTEGER NOT NULL,
    start_offset     INTEGER NOT NULL,
    end_offset       INTEGER NOT NULL,
    earliest_packet  INTEGER NOT NULL,
    earliest_capture INTEGER NOT NULL,
    latest_packet    INTEGER NOT NULL,
    latest_capture   INTEGER NOT NULL,
    divergent        INTEGER NOT NULL,
    PRIMARY KEY (session_id, direction, revision, idx),
    FOREIGN KEY (session_id, direction, revision)
        REFERENCES revisions(session_id, direction, revision)
);

CREATE INDEX IF NOT EXISTS idx_runs_span
    ON runs(session_id, direction, revision, start_offset, end_offset);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-65536")  # 约 64 MiB 页缓存上限
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    _migrate_packets(conn)


def _migrate_packets(conn: sqlite3.Connection) -> None:
    """旧库升级：packets 表补 ack / sack 列（既有行均为 NULL = 无确认内容）。"""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(packets)")}
    if "ack" not in cols:
        conn.execute("ALTER TABLE packets ADD COLUMN ack INTEGER")
    if "sack" not in cols:
        conn.execute("ALTER TABLE packets ADD COLUMN sack TEXT")


@contextmanager
def transaction(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


# ---------------- 会话 / 报文 ----------------


def create_session(conn: sqlite3.Connection, session_id: str) -> None:
    try:
        conn.execute("INSERT INTO sessions(id) VALUES (?)", (session_id,))
    except sqlite3.IntegrityError:
        pass  # 幂等：已存在直接复用


def session_exists(conn: sqlite3.Connection, session_id: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sessions WHERE id=?", (session_id,)
    ).fetchone() is not None


def current_revision(conn: sqlite3.Connection, session_id: str, direction: str) -> int | None:
    row = conn.execute(
        "SELECT MAX(revision) AS m FROM revisions"
        " WHERE session_id=? AND direction=?",
        (session_id, direction),
    ).fetchone()
    return row["m"]


def _packet_digest(seq: int, syn: int, fin: int, payload: bytes,
                   ack: int | None, sack_norm) -> str:
    """报文内容哈希。无 ACK/SACK 时与旧版算法逐字节一致（旧库幂等重传安全）。"""
    h = hashlib.sha256(
        seq.to_bytes(4, "little")
        + bytes([syn, fin])
        + payload
    )
    if ack is not None:
        h.update(b"\x01" + ack.to_bytes(4, "little"))
    if sack_norm:
        h.update(b"\x02" + json.dumps(sack_norm, separators=(",", ":")).encode("ascii"))
    return h.hexdigest()


def _normalize_sack(sack) -> list | None:
    """SACK 块规范化：排序后块顺序不影响内容同一性；空列表视为无 SACK。"""
    if not sack:
        return None
    return sorted([int(b[0]), int(b[1])] for b in sack)


def add_packets(conn: sqlite3.Connection, session_id: str, direction: str, packets) -> None:
    """批量写入报文。同 (direction, capture) 已存在：内容一致则忽略，冲突则 409。

    packets: [(capture, seq, syn, fin, payload), ...] 旧格式，或
             [(capture, seq, syn, fin, payload, ack, sack), ...]；
             ack 为 32 位确认号或 None，sack 为 [(l, r), ...] 半开块或 None。
    内容哈希涵盖 ACK/SACK：同捕获序号但确认内容不同同样判 409。
    """
    insert_sql = (
        "INSERT INTO packets(session_id, direction, capture, seq, syn, fin, payload,"
        " ack, sack, sha256) VALUES (?,?,?,?,?,?,?,?,?,?)"
    )
    # 先做批内重复捕获序号检查（seq/SYN/FIN/载荷/ACK/SACK 任一不同即冲突）
    seen: dict[int, str] = {}
    rows = []
    for pkt in packets:
        capture, seq, syn, fin, payload = pkt[:5]
        ack = pkt[5] if len(pkt) > 5 else None
        sack_norm = _normalize_sack(pkt[6] if len(pkt) > 6 else None)
        digest = _packet_digest(seq, syn, fin, payload, ack, sack_norm)
        if capture in seen and seen[capture] != digest:
            raise RevisionConflict(
                current_revision(conn, session_id, direction) or 0,
                f"批次内捕获序号 {capture} 出现多次且内容不同",
            )
        seen[capture] = digest
        rows.append((
            session_id, direction, capture, seq, syn, fin, payload,
            ack,
            json.dumps(sack_norm, separators=(",", ":")) if sack_norm else None,
            digest,
        ))

    with transaction(conn):
        for row in rows:
            capture = row[2]
            old = conn.execute(
                "SELECT sha256 FROM packets WHERE session_id=? AND direction=? AND capture=?",
                (session_id, direction, capture),
            ).fetchone()
            if old is not None:
                if old["sha256"] != row[9]:
                    raise RevisionConflict(
                        current_revision(conn, session_id, direction) or 0,
                        f"捕获序号 {capture} 已存在且报文内容不同",
                    )
                continue  # 幂等重传
            conn.execute(insert_sql, row)


def iter_ack_packets(conn: sqlite3.Connection, session_id: str, direction: str):
    """按捕获序号升序取该方向所有带 ACK 或 SACK 的报文（对端确认证据）。"""
    return conn.execute(
        "SELECT id, capture, ack, sack FROM packets"
        " WHERE session_id=? AND direction=?"
        " AND (ack IS NOT NULL OR sack IS NOT NULL) ORDER BY capture",
        (session_id, direction),
    ).fetchall()


# ---------------- 发布修订 ----------------


def _load_snapshot(conn: sqlite3.Connection, session_id: str, direction: str) -> DirectionSnapshot:
    rows = conn.execute(
        "SELECT id, capture, seq, syn, fin, length(payload) AS plen "
        "FROM packets WHERE session_id=? AND direction=? ORDER BY id",
        (session_id, direction),
    ).fetchall()

    syn_packets = [(r["id"], r["capture"], r["seq"]) for r in rows if r["syn"]]
    isn = None
    if len(syn_packets) == 1:
        isn = syn_packets[0][2]

    fin_packets = [(r["id"], r["capture"], r["seq"]) for r in rows if r["fin"]]
    fin_pos = None
    if fin_packets and isn is not None:
        # FIN 占用一个序号：纯 FIN 占用其 seq；带数据时占用 seq+plen；
        # SYN+FIN（SYN 也占一号）时再加 1。fin_pos 即 FIN 前数据末端（exclusive）。
        info_by_id = {r["id"]: (r["plen"], 1 if r["syn"] else 0) for r in rows}
        fin_offsets = {
            relative_offset(seq + info_by_id[pid][0] + info_by_id[pid][1], isn)
            for pid, _, seq in fin_packets
        }
        if len(fin_offsets) != 1:
            raise PublishRejected(
                f"FIN 位置冲突：观察到 {len(fin_offsets)} 个不同 FIN 位置"
            )
        fin_pos = fin_offsets.pop()
        if not (1 <= fin_pos <= LIMIT):
            raise PublishRejected(
                f"FIN 位置 {fin_pos} 超出合法范围（1..2^31）"
            )

    segments: list[Segment] = []
    if isn is not None:
        for r in rows:
            if r["syn"]:
                # SYN 占偏移 0。SYN 报文可携带数据（如 TFO），数据从偏移 1 开始。
                if not r["plen"]:
                    continue
                start, length = 1, r["plen"]
            else:
                start = relative_offset(r["seq"], isn)
                length = r["plen"]
            if length:
                # 线性化到 [start, start+length]，越过 2^31 由 validate 拒绝
                if length > LIMIT:
                    raise PublishRejected(
                        f"报文 capture={r['capture']} 覆盖长度 {length} 越过 2^31"
                    )
                segments.append(Segment(r["id"], r["capture"], start, start + length))
            # 纯 FIN / 纯 ACK：无字节区间，仅 fin 标记参与 fin_pos
    else:
        # 没有 SYN 时无法换算偏移；validate_and_resolve 会先报“缺少唯一 SYN”
        pass

    return DirectionSnapshot(
        isn=isn,
        syn_packets=syn_packets,
        fin_pos=fin_pos,
        fin_packets=fin_packets,
        segments=segments,
    )


def publish_revision(
    conn: sqlite3.Connection,
    session_id: str,
    direction: str,
    expected_revision: int,
) -> dict:
    """按预期修订号发布；成功返回新修订摘要，冲突抛 RevisionConflict。"""
    with transaction(conn):
        cur = current_revision(conn, session_id, direction) or 0
        if expected_revision != cur:
            raise RevisionConflict(cur, "期望修订号与当前修订号不一致")

        snap = _load_snapshot(conn, session_id, direction)
        isn, fin_pos, segments = validate_and_resolve(snap)

        # 扫描线裁决 + 合并相邻同源行程（生成器逐批写出，避免一次性大列表）
        atomic = sweep_segments(segments)
        merged = list(merge_runs(atomic))
        gaps = gap_intervals(merged, fin_pos)
        complete = runs_complete(merged, fin_pos)

        new_revision = (cur or 0) + 1
        conn.execute(
            "INSERT INTO revisions(session_id, direction, revision, isn, fin_pos,"
            " complete, run_count, gaps) VALUES (?,?,?,?,?,?,?,?)",
            (
                session_id,
                direction,
                new_revision,
                isn,
                fin_pos,
                1 if complete else 0,
                len(merged),
                json.dumps(gaps, separators=(",", ":")),
            ),
        )

        BATCH = 5000
        batch: list[tuple] = []
        for idx, r in enumerate(merged):
            batch.append((
                session_id,
                direction,
                new_revision,
                idx,
                r["start"],
                r["end"],
                r["earliest_packet"],
                r["earliest_capture"],
                r["latest_packet"],
                r["latest_capture"],
                1 if r["divergent"] else 0,
            ))
            if len(batch) >= BATCH:
                conn.executemany(_RUN_INSERT, batch)
                batch.clear()
        if batch:
            conn.executemany(_RUN_INSERT, batch)

    return {
        "revision": new_revision,
        "isn": isn,
        "fin_pos": fin_pos,
        "complete": complete,
        "run_count": len(merged),
        "gaps": gaps,
    }


_RUN_INSERT = (
    "INSERT INTO runs(session_id, direction, revision, idx, start_offset,"
    " end_offset, earliest_packet, earliest_capture, latest_packet,"
    " latest_capture, divergent) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
)


# ---------------- 查询 ----------------


def get_revision_meta(conn: sqlite3.Connection, session_id: str, direction: str,
                      revision: int) -> dict | None:
    row = conn.execute(
        "SELECT revision, isn, fin_pos, complete, run_count, gaps, created_at"
        " FROM revisions WHERE session_id=? AND direction=? AND revision=?",
        (session_id, direction, revision),
    ).fetchone()
    if row is None:
        return None

    return {
        "revision": row["revision"],
        "isn": row["isn"],
        "fin_pos": row["fin_pos"],
        "complete": bool(row["complete"]),
        "run_count": row["run_count"],
        "gaps": json.loads(row["gaps"]),
        "created_at": row["created_at"],
    }


def iter_runs(
    conn: sqlite3.Connection,
    session_id: str,
    direction: str,
    revision: int,
    start_idx: int,
    min_end: int,
    limit: int,
):
    """按 idx 升序顺序取一页修订 run（idx >= start_idx 且 end_offset > min_end）。

    供字节特征定位流式扫描：调用方把上一批最后一条的 idx+1 作为 start_idx
    继续取下一批；缺口由相邻 run 的 start/end 差值判定，不在 SQL 层补全。
    """
    return conn.execute(
        "SELECT idx, start_offset AS s, end_offset AS e,"
        " earliest_packet AS ep, earliest_capture AS ec,"
        " latest_packet AS lp, latest_capture AS lc, divergent AS d"
        " FROM runs WHERE session_id=? AND direction=? AND revision=?"
        " AND idx>=? AND end_offset>? ORDER BY idx LIMIT ?",
        (session_id, direction, revision, start_idx, min_end, limit),
    ).fetchall()


def payload_slices(conn: sqlite3.Connection, refs):
    """refs: [(packet_id, logical_start, logical_end)] -> 对应字节片列表。

    逻辑偏移先换算为报文载荷内索引；同一报文只读取其所需窗口一次。
    ISN 取该报文所属会话/方向最新修订的 ISN（旧修订同源同 ISN，不影响取字节）。
    """
    wanted: dict[int, set[tuple[int, int]]] = {}
    spans: dict[int, int] = {}
    for pid, start, end in refs:
        wanted.setdefault(pid, set()).add((start, end))
        if pid not in spans:
            r = conn.execute(
                "SELECT pk.seq AS seq, pk.syn AS syn, rev.isn AS isn"
                " FROM packets pk JOIN revisions rev"
                " ON rev.session_id = pk.session_id AND rev.direction = pk.direction"
                " WHERE pk.id=? ORDER BY rev.revision DESC LIMIT 1",
                (pid,),
            ).fetchone()
            # SYN 占偏移 0，其携带的数据从偏移 1 开始；其余数据按 seq 换算
            spans[pid] = 1 if r["syn"] else relative_offset(r["seq"], r["isn"])

    windows: dict[int, tuple[bytes, int]] = {}
    for pid, ranges in wanted.items():
        pstart = spans[pid]
        lo = min(a for a, _ in ranges)
        hi = max(b for _, b in ranges)
        row = conn.execute(
            # SQLite substr 偏移从 1 开始；只截取本页所需窗口
            "SELECT substr(payload, ?, ?) AS part FROM packets WHERE id=?",
            (lo - pstart + 1, hi - lo, pid),
        ).fetchone()
        windows[pid] = (row["part"] if row is not None else b"", lo)

    out = []
    for pid, start, end in refs:
        part, base = windows[pid]
        out.append(bytes(part[start - base:end - base]))
    return out
