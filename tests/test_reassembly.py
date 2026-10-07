"""功能测试：乱序重组 / 回绕 / 2^31 / FIN 规则 / 修订 / 分页。"""

import base64
import os
import tempfile

import pytest

from app import db
from app.reassembly import LIMIT, MOD, Segment


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "t.db"))
    db.init_db(c)
    yield c
    c.close()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def upload(conn, sid, d, packets):
    db.create_session(conn, sid)
    db.add_packets(conn, sid, d, packets)


# ---------- 纯引擎：earliest / latest 裁决 ----------


def test_sweep_earliest_and_latest():
    from app.reassembly import sweep_segments, merge_runs

    # 三个重叠段：capture 顺序故意打乱
    # pkt1 cap=10: [1,3)="AB"; pkt2 cap=20: [2,4)="xC"; pkt3 cap=5 : [3,5)="YZ"
    segs = [
        Segment(packet_id=1, capture=10, start=1, end=3),
        Segment(packet_id=2, capture=20, start=2, end=4),
        Segment(packet_id=3, capture=5, start=3, end=5),
    ]
    runs = list(merge_runs(sweep_segments(segs)))
    owners = [(r["start"], r["end"], r["earliest_capture"], r["latest_capture"])
              for r in runs]
    # [1,2): 10/10; [2,3): 10/20; [3,4): 5/20; [4,5): 5/5
    assert owners == [(1, 2, 10, 10), (2, 3, 10, 20), (3, 4, 5, 20), (4, 5, 5, 5)]


# ---------- 端到端：上传顺序无关 ----------


def test_upload_order_independent(conn):
    from app.report import build_page

    sid = "s1"
    isn = 1000
    packets_correct = [
        (1, isn, 1, 0, b""),                # SYN
        (2, isn + 1, 0, 0, b"AB"),
        (3, isn + 3, 0, 0, b"CD"),
        (4, isn + 5, 0, 1, b""),            # FIN 占 seq=isn+5 => fin_pos 5
    ]
    # 乱序、倒序上传
    upload(conn, sid, "c2s", list(reversed(packets_correct)))

    res = db.publish_revision(conn, sid, "c2s", 0)
    assert res["revision"] == 1
    assert res["complete"] is True
    assert res["fin_pos"] == 5
    assert res["gaps"] == []

    page = build_page(conn, sid, "c2s", 1, 1, 1024, 100)
    assert base64.b64decode(page["earliest_base64"]) == b"ABCD"
    assert base64.b64decode(page["latest_base64"]) == b"ABCD"
    assert page["complete"] is True
    assert page["page"]["done"] is True


def test_overlap_two_reassemblies_and_divergence(conn):
    from app.report import build_page

    sid = "s2"
    isn = 0
    upload(conn, sid, "c2s", [
        (1, isn, 1, 0, b""),
        (10, isn + 1, 0, 0, b"AB"),
        (20, isn + 2, 0, 0, b"xC"),
    ])
    db.publish_revision(conn, sid, "c2s", 0)
    page = build_page(conn, sid, "c2s", 1, 1, 1024, 100)
    # earliest: 最早捕获 cap=10 持有重叠字节 => ABC
    # latest:   最晚捕获 cap=20 覆盖偏移2 => AxC
    assert base64.b64decode(page["earliest_base64"]) == b"ABC"
    assert base64.b64decode(page["latest_base64"]) == b"AxC"
    assert page["divergence_intervals"] == [[2, 3]]


def test_late_low_capture_creates_new_revision_old_report_unchanged(conn):
    from app.report import build_page

    sid = "s3"
    isn = 0
    upload(conn, sid, "c2s", [
        (1, isn, 1, 0, b""),
        (20, isn + 1, 0, 0, b"AB"),
    ])
    db.publish_revision(conn, sid, "c2s", 0)  # rev1: earliest=latest=AB
    p1 = build_page(conn, sid, "c2s", 1, 1, 1024, 100)
    assert base64.b64decode(p1["earliest_base64"]) == b"AB"

    # 更晚到达、但捕获序号更小的报文：earliest 翻转，latest 不变
    upload(conn, sid, "c2s", [(10, isn + 1, 0, 0, b"xC")])
    res = db.publish_revision(conn, sid, "c2s", 1)
    assert res["revision"] == 2

    p1_old = build_page(conn, sid, "c2s", 1, 1, 1024, 100)
    assert base64.b64decode(p1_old["earliest_base64"]) == b"AB"  # 旧报告不变

    p2 = build_page(conn, sid, "c2s", 2, 1, 1024, 100)
    assert base64.b64decode(p2["earliest_base64"]) == b"xC"
    assert base64.b64decode(p2["latest_base64"]) == b"AB"


def test_expected_revision_conflict(conn):
    sid = "s4"
    upload(conn, sid, "c2s", [(1, 5, 1, 0, b"")])
    db.publish_revision(conn, sid, "c2s", 0)
    with pytest.raises(db.RevisionConflict) as ei:
        db.publish_revision(conn, sid, "c2s", 0)  # 仍期望 0，实际 1
    assert ei.value.current_revision == 1


def test_same_capture_different_content_conflicts(conn):
    sid = "s5"
    upload(conn, sid, "c2s", [(1, 5, 1, 0, b"")])
    with pytest.raises(db.RevisionConflict):
        db.add_packets(conn, sid, "c2s", [(1, 6, 1, 0, b"")])
    # 相同内容幂等
    db.add_packets(conn, sid, "c2s", [(1, 5, 1, 0, b"")])


def test_sequencerollover_locates_payload(conn):
    from app.report import build_page

    sid = "s6"
    isn = 0xFFFFFFFE
    upload(conn, sid, "c2s", [
        (1, isn, 1, 0, b""),
        # seq=0xFFFFFFFF: rel=1 "X"; seq=0: rel=2 "Y"; seq=1: rel=3 "Z"
        (2, 0xFFFFFFFF, 0, 0, b"X"),
        (4, 1, 0, 0, b"Z"),
        (3, 0, 0, 0, b"Y"),
    ])
    db.publish_revision(conn, sid, "c2s", 0)
    page = build_page(conn, sid, "c2s", 1, 1, 1024, 100)
    assert base64.b64decode(page["earliest_base64"]) == b"XYZ"


def test_fin_position_conflict_rejected(conn):
    sid = "s7"
    upload(conn, sid, "c2s", [
        (1, 100, 1, 0, b""),
        (2, 105, 0, 1, b""),   # fin pos 5
        (3, 106, 0, 1, b""),   # fin pos 6
    ])
    with pytest.raises(db.PublishRejected, match="FIN 位置冲突"):
        db.publish_revision(conn, sid, "c2s", 0)


def test_data_after_fin_rejected(conn):
    sid = "s8"
    upload(conn, sid, "c2s", [
        (1, 100, 1, 0, b""),
        (2, 104, 0, 1, b""),   # fin pos 4
        (3, 104, 0, 0, b"Z"),  # 字节 [4,5)，FIN 之后
    ])
    with pytest.raises(db.PublishRejected, match="FIN 后"):
        db.publish_revision(conn, sid, "c2s", 0)


def test_offset_at_2pow31_rejected(conn):
    sid = "s9"
    isn = 0
    upload(conn, sid, "c2s", [
        (1, isn, 1, 0, b""),
        # 起始偏移恰好 2^31
        (2, LIMIT % MOD, 0, 0, b"A"),
    ])
    with pytest.raises(db.PublishRejected, match="2\\^31"):
        db.publish_revision(conn, sid, "c2s", 0)


def test_fin_at_2pow31_allowed_and_gap_incomplete(conn):
    from app.report import build_page

    sid = "s10"
    upload(conn, sid, "c2s", [
        (1, 0, 1, 0, b""),
        (2, 1, 0, 0, b"A"),               # 偏移 1
        (3, LIMIT, 0, 1, b""),            # FIN 占 seq=2^31 => fin_pos 2^31
    ])
    res = db.publish_revision(conn, sid, "c2s", 0)
    assert res["fin_pos"] == LIMIT
    assert res["complete"] is False
    assert res["gaps"] == [[2, LIMIT]]

    page = build_page(conn, sid, "c2s", 1, 1, 1024, 100)
    assert base64.b64decode(page["earliest_base64"]) == b"A"
    assert page["page"]["done"] is True  # 缺口不产生页
    assert page["gaps"] == [[2, LIMIT]]


def test_missing_syn_rejected(conn):
    sid = "s11"
    upload(conn, sid, "c2s", [(2, 100, 0, 0, b"AB")])
    with pytest.raises(db.PublishRejected, match="缺少唯一 SYN"):
        db.publish_revision(conn, sid, "c2s", 0)


def test_two_syns_rejected(conn):
    sid = "s12"
    upload(conn, sid, "c2s", [
        (1, 100, 1, 0, b""),
        (2, 200, 1, 0, b""),
    ])
    with pytest.raises(db.PublishRejected, match="SYN"):
        db.publish_revision(conn, sid, "c2s", 0)


def test_gaps_not_zero_padded_and_pagination(conn):
    from app.report import build_page

    sid = "s13"
    upload(conn, sid, "c2s", [
        (1, 0, 1, 0, b""),
        (2, 1, 0, 0, b"AB"),    # [1,3)
        (3, 10, 0, 0, b"CD"),   # [10,12)
    ])
    db.publish_revision(conn, sid, "c2s", 0)
    p1 = build_page(conn, sid, "c2s", 1, 1, max_bytes=2, max_runs=100)
    assert base64.b64decode(p1["earliest_base64"]) == b"AB"
    assert p1["page"]["next_offset"] == 3

    # 从缺口中间开始：定位到下一个 run，不补零
    p2 = build_page(conn, sid, "c2s", 1, 5, max_bytes=64, max_runs=100)
    assert base64.b64decode(p2["earliest_base64"]) == b"CD"
    assert p2["runs"][0]["start"] == 10
    assert p2["gaps"] == [[3, 10]]


def test_single_run_split_across_pages(conn):
    from app.report import build_page

    sid = "s15"
    upload(conn, sid, "c2s", [
        (1, 0, 1, 0, b""),
        (2, 1, 0, 0, b"ABCDEFGH"),  # 单个 run [1,9)
    ])
    db.publish_revision(conn, sid, "c2s", 0)

    p1 = build_page(conn, sid, "c2s", 1, 1, max_bytes=3, max_runs=100)
    assert base64.b64decode(p1["earliest_base64"]) == b"ABC"
    assert p1["page"]["next_offset"] == 4
    assert p1["runs"][0]["start"] == 1 and p1["runs"][0]["end"] == 4

    p2 = build_page(conn, sid, "c2s", 1, 4, max_bytes=3, max_runs=100)
    assert base64.b64decode(p2["earliest_base64"]) == b"DEF"
    assert p2["page"]["next_offset"] == 7

    p3 = build_page(conn, sid, "c2s", 1, 7, max_bytes=3, max_runs=100)
    assert base64.b64decode(p3["earliest_base64"]) == b"GH"
    assert p3["page"]["next_offset"] is None
    assert p3["page"]["done"] is True


def test_syn_fin_alone_is_complete(conn):
    sid = "s17"
    upload(conn, sid, "c2s", [(1, 1000, 1, 1, b"")])  # SYN+FIN，无数据
    res = db.publish_revision(conn, sid, "c2s", 0)
    assert res["fin_pos"] == 1
    assert res["complete"] is True
    assert res["gaps"] == []


def test_syn_data_fin_in_one_packet(conn):
    from app.report import build_page

    sid = "s18"
    upload(conn, sid, "c2s", [(1, 1000, 1, 1, b"AB")])  # SYN+数据+FIN 同包
    res = db.publish_revision(conn, sid, "c2s", 0)
    assert res["fin_pos"] == 3  # SYN 占 1 号 + 2 数据字节
    assert res["complete"] is True
    page = build_page(conn, sid, "c2s", 1, 1, 1024, 100)
    assert base64.b64decode(page["earliest_base64"]) == b"AB"


def test_syn_with_payload_starts_at_offset_one(conn):
    from app.report import build_page

    sid = "s16"
    upload(conn, sid, "c2s", [
        (1, 1000, 1, 0, b"AB"),   # SYN 占 0，载荷 AB 占偏移 1..2
        (2, 1003, 0, 0, b"CD"),
    ])
    db.publish_revision(conn, sid, "c2s", 0)
    page = build_page(conn, sid, "c2s", 1, 1, 1024, 100)
    assert base64.b64decode(page["earliest_base64"]) == b"ABCD"
    assert page["runs"][0]["start"] == 1


def test_complete_requires_fin_and_no_gap_before_it(conn):
    sid = "s14"
    upload(conn, sid, "c2s", [
        (1, 0, 1, 0, b""),
        (2, 1, 0, 0, b"AB"),
        (4, 4, 0, 1, b""),  # FIN 占 seq=4 => fin_pos 4，[3,4) 缺口
    ])
    res = db.publish_revision(conn, sid, "c2s", 0)
    assert res["complete"] is False
    assert res["gaps"] == [[3, 4]]
