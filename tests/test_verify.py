"""对端确认缺口核验（/verify）端到端测试。

覆盖：
* 旧格式报文继续可用；ACK/SACK 上传、同 capture 异确认内容 409
* 以目标修订 SYN 锚换算反向 ACK/SACK：累计 ACK=[1,cum)，SACK 各块独立
* 已确认但未捕获 / 无确认依据 两类区间；后者不等于未送达
* 重复/倒序 ACK、重叠 SACK 不重复计数；SACK 上界不当累计确认
* 半序号窗口外确认忽略；SACK 无 ACK / 字段非法 422；未知修订 404
* 晚到证据更新核验，但旧版报告与定位不变；纯 SYN/FIN 核验 FIN 前缺口
"""

import base64
import importlib

import pytest
from fastapi.testclient import TestClient

MOD = 1 << 32
LIMIT = 1 << 31


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "verify.db")
    monkeypatch.setenv("DB_PATH", db_path)
    from app import main

    importlib.reload(main)
    main.DB_PATH = db_path
    with TestClient(main.app) as c:
        yield c


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def setup_gappy(client, sid="ack", isn=1000):
    """c2s：SYN(isn)，AB@1、CD@5、FIN@7 → 冻结缺口 [3,5)。"""
    client.post("/sessions", json={"session_id": sid})
    r = client.post(f"/sessions/{sid}/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": isn, "syn": True},
        {"capture": 2, "seq": isn + 1, "payload": b64(b"AB")},
        {"capture": 3, "seq": isn + 5, "payload": b64(b"CD")},
        {"capture": 4, "seq": isn + 7, "fin": True},
    ]})
    assert r.status_code == 202
    r = client.post(f"/sessions/{sid}/directions/c2s/revisions",
                    json={"expected_revision": 0})
    assert r.status_code == 201
    assert r.json()["gaps"] == [[3, 5]]


def verify(client, sid="ack", rev=1, d="c2s"):
    return client.get(
        f"/sessions/{sid}/directions/{d}/revisions/{rev}/verify"
    )


def test_legacy_packets_still_work_and_no_ack_means_unacknowledged(client):
    setup_gappy(client)
    # 反向一条旧格式纯 ACK？旧格式没有 ack 字段 → 不构成确认依据
    r = client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 1, "seq": 9000, "syn": True},
    ]})
    assert r.status_code == 202
    body = verify(client).json()
    assert body["cumulative_ack"]["offset"] == 0
    assert body["cumulative_ack"]["source"] is None
    assert body["sack_blocks"] == []
    assert body["acknowledged_gaps"] == []
    assert body["unacknowledged_gaps"] == [[3, 5]]
    assert "不等于未送达" in body["note"]


def test_cumulative_ack_covers_prefix_of_gap(client):
    setup_gappy(client)
    # ack=isn+4 → cum=4：覆盖 [1,4)，与缺口 [3,5) 交 [3,4)
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 7, "seq": 9000, "ack": 1004},
    ]})
    body = verify(client).json()
    assert body["cumulative_ack"]["offset"] == 4
    assert body["cumulative_ack"]["source"] == {
        "packet_id": 5, "capture": 7, "ack": 1004
    }
    assert body["acknowledged_gaps"] == [[3, 4]]
    assert body["unacknowledged_gaps"] == [[4, 5]]


def test_full_gap_acknowledged(client):
    setup_gappy(client)
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 7, "seq": 9000, "ack": 1005},  # cum=5 覆盖整个缺口
    ]})
    body = verify(client).json()
    assert body["acknowledged_gaps"] == [[3, 5]]
    assert body["unacknowledged_gaps"] == []


def test_sack_covers_only_its_blocks(client):
    setup_gappy(client)
    # cum=3（[1,3)，不碰缺口）；SACK [isn+4,isn+5) → 偏移 [4,5)
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 7, "seq": 9000, "ack": 1003,
         "sack": [{"left": 1004, "right": 1005}]},
    ]})
    body = verify(client).json()
    assert body["cumulative_ack"]["offset"] == 3
    assert body["sack_blocks"][0]["start"] == 4
    assert body["sack_blocks"][0]["end"] == 5
    assert body["acknowledged_gaps"] == [[4, 5]]
    assert body["unacknowledged_gaps"] == [[3, 4]]


def test_cum_plus_sack_split_gap(client):
    setup_gappy(client)
    # cum=4 确认 [3,4)；SACK [5,7) 在缺口外（5 为右邻起点）→ 缺口 [4,5) 仍无依据
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 8, "seq": 9001, "ack": 1004,
         "sack": [{"left": 1005, "right": 1007}]},
    ]})
    body = verify(client).json()
    # SACK 上界 7 绝不能抬升累计确认
    assert body["cumulative_ack"]["offset"] == 4
    assert body["acknowledged_gaps"] == [[3, 4]]
    assert body["unacknowledged_gaps"] == [[4, 5]]
    # 展示的 SACK 块 [5,7) 与缺口无关，但仍如实列出
    assert [b["start"] for b in body["sack_blocks"]] == [5]


def test_duplicate_and_reverse_order_acks_not_double_counted(client):
    setup_gappy(client)
    # 倒序上传：先大后小，再加重复；累计只认窗口内最大值
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 30, "seq": 9000, "ack": 1004},
        {"capture": 10, "seq": 9001, "ack": 1002},
        {"capture": 20, "seq": 9002, "ack": 1004},  # 重复 ACK
    ]})
    body = verify(client).json()
    assert body["cumulative_ack"]["offset"] == 4
    # 并列最大取最晚捕获（30）
    assert body["cumulative_ack"]["source"]["capture"] == 30
    assert body["acknowledged_gaps"] == [[3, 4]]
    assert body["unacknowledged_gaps"] == [[4, 5]]


def test_overlapping_sacks_merged_not_double_counted(client):
    setup_gappy(client)
    # cum=3；两个重叠 SACK 块覆盖 [4,5) 与 [4,6)，合并后只算一次
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 10, "seq": 9000, "ack": 1003,
         "sack": [{"left": 1004, "right": 1005}]},
        {"capture": 11, "seq": 9001, "ack": 1003,
         "sack": [{"left": 1004, "right": 1006}]},
    ]})
    body = verify(client).json()
    assert body["sack_blocks"] == [{
        "start": 4, "end": 6,
        "sources": [
            {"packet_id": 5, "capture": 10, "ack": 1003},
            {"packet_id": 6, "capture": 11, "ack": 1003},
        ],
    }]
    # 与缺口 [3,5) 的交集只有一份 [4,5)
    assert body["acknowledged_gaps"] == [[4, 5]]
    assert body["unacknowledged_gaps"] == [[3, 4]]


def test_sack_block_clipped_to_cumulative(client):
    setup_gappy(client)
    # SACK 块 [2,5)，其中 [2,4) 已被 cum=4 覆盖；展示时裁成 [4,5)，
    # 已覆盖部分不重复计为 SACK 依据
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 9000, "ack": 1004,
         "sack": [{"left": 1002, "right": 1005}]},
    ]})
    body = verify(client).json()
    assert body["sack_blocks"] == [{
        "start": 4, "end": 5,
        "sources": [{"packet_id": 5, "capture": 9, "ack": 1004}],
    }]
    # [3,4) 由累计 ACK 覆盖、[4,5) 由 SACK 覆盖：相邻但来源不同，保持分段
    assert body["acknowledged_gaps"] == [[3, 4], [4, 5]]
    assert body["unacknowledged_gaps"] == []


def test_out_of_window_ack_ignored(client):
    setup_gappy(client)
    # rel(ack) = 2^31 + 1（越窗）→ 忽略整条，其 SACK 也忽略
    bad_ack = (1000 + LIMIT + 1) % MOD
    r = client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 9000, "ack": bad_ack,
         "sack": [{"left": 1004, "right": 1005}]},
    ]})
    assert r.status_code == 202
    body = verify(client).json()
    assert body["cumulative_ack"]["offset"] == 0
    assert body["cumulative_ack"]["source"] is None
    assert body["sack_blocks"] == []
    assert body["ignored_outside_window"] == 1
    assert body["acknowledged_gaps"] == []
    assert body["unacknowledged_gaps"] == [[3, 5]]


def test_ack_at_window_boundary_accepted(client):
    # ISN=0；ACK 恰为 2^31（窗口内，合法末端）→ cum=2^31 全覆盖
    client.post("/sessions", json={"session_id": "b"})
    client.post("/sessions/b/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AB")},
        {"capture": 3, "seq": 5, "payload": b64(b"CD")},
    ]})
    client.post("/sessions/b/directions/c2s/revisions",
                json={"expected_revision": 0})
    client.post("/sessions/b/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 7000, "ack": LIMIT},
    ]})
    body = verify(client, sid="b").json()
    assert body["cumulative_ack"]["offset"] == LIMIT
    assert body["acknowledged_gaps"] == [[3, 5]]
    assert body["unacknowledged_gaps"] == []


def test_sack_wrapping_block_ignored(client):
    # ISN=0xFFFFFFF0；原始 SACK 块 left<right 通过上传校验，
    # 但相对换算后回绕（lo>=hi）→ 核验时丢弃并计数
    isn = MOD - 16
    client.post("/sessions", json={"session_id": "w"})
    client.post("/sessions/w/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": isn, "syn": True},
        {"capture": 2, "seq": (isn + 1) % MOD, "payload": b64(b"AB")},
        {"capture": 3, "seq": (isn + 5) % MOD, "payload": b64(b"CD")},
    ]})
    client.post("/sessions/w/directions/c2s/revisions",
                json={"expected_revision": 0})
    # 合法累计 ACK=3，外加一个换算后回绕的 SACK 原始块
    ack = (isn + 3) % MOD
    client.post("/sessions/w/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 20, "ack": ack,
         "sack": [{"left": (isn - 2) % MOD, "right": (isn + 2) % MOD}]},
    ]})
    body = verify(client, sid="w").json()
    assert body["cumulative_ack"]["offset"] == 3
    assert body["sack_blocks"] == []
    assert body["ignored_outside_window"] == 1
    assert body["unacknowledged_gaps"] == [[3, 5]]


def test_sack_without_ack_422(client):
    setup_gappy(client)
    r = client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 9000,
         "sack": [{"left": 1004, "right": 1005}]},
    ]})
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "sack_without_ack"


def test_sack_accepts_pair_form(client):
    setup_gappy(client)
    # SACK 块也接受 [left,right] 二元组写法
    r = client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 7, "seq": 9000, "ack": 1003, "sack": [[1004, 1005]]},
    ]})
    assert r.status_code == 202
    body = verify(client).json()
    assert body["sack_blocks"][0]["start"] == 4
    assert body["acknowledged_gaps"] == [[4, 5]]


def test_invalid_sack_block_422(client):
    setup_gappy(client)
    r = client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 9000, "ack": 1004,
         "sack": [{"left": 1005, "right": 1005}]},  # 空块
    ]})
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_sack"


def test_ack_field_out_of_range_422(client):
    setup_gappy(client)
    r = client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 9000, "ack": 2 ** 32},
    ]})
    assert r.status_code == 422


def test_same_capture_different_ack_conflict_409(client):
    setup_gappy(client)
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 9000, "ack": 1003},
    ]})
    # 同 capture=9 改成不同 ACK → 409
    r = client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 9000, "ack": 1004},
    ]})
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "capture_conflict"

    # 同 capture 增加 SACK 也算内容不同 → 409
    r = client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 9000, "ack": 1003,
         "sack": [{"left": 1004, "right": 1005}]},
    ]})
    assert r.status_code == 409


def test_same_capture_same_content_idempotent(client):
    setup_gappy(client)
    payload = [{"capture": 9, "seq": 9000, "ack": 1004,
                "sack": [{"left": 1005, "right": 1006}]}]
    r1 = client.post("/sessions/ack/directions/s2c/packets",
                     json={"packets": payload})
    r2 = client.post("/sessions/ack/directions/s2c/packets",
                     json={"packets": payload})
    assert r1.status_code == r2.status_code == 202


def test_unknown_revision_and_latest_404(client):
    setup_gappy(client)
    assert verify(client, rev=99).status_code == 404
    # 从未发布过修订的方向，latest 也 404
    client.post("/sessions", json={"session_id": "nr"})
    r = client.get("/sessions/nr/directions/c2s/revisions/latest/verify")
    assert r.status_code == 404


def test_late_evidence_updates_verification_but_report_frozen(client):
    setup_gappy(client)
    # 初始：cum=3 → [3,4)? cum=3 覆盖 [1,3)，与缺口无交
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 7, "seq": 9000, "ack": 1003},
    ]})
    v1 = verify(client).json()
    assert v1["acknowledged_gaps"] == []
    assert v1["unacknowledged_gaps"] == [[3, 5]]

    # 晚到更强证据：cum=5，核验立即更新（修订号不变、无新发布）
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 8, "seq": 9001, "ack": 1005},
    ]})
    v2 = verify(client).json()
    assert v2["revision"] == 1
    assert v2["acknowledged_gaps"] == [[3, 5]]
    assert v2["unacknowledged_gaps"] == []

    # 报告缺口与字节不变（旧版报告不随确认证据变化）
    rep = client.get(
        "/sessions/ack/directions/c2s/revisions/1/report"
    ).json()
    assert rep["gaps"] == [[3, 5]]
    assert rep["earliest_base64"] == b64(b"ABCD")


def test_verification_uses_syn_anchor_of_target_revision(client):
    # 反向确认号以 c2s 修订的 ISN 换算，与 s2c 自身是否有 SYN 无关
    setup_gappy(client)
    # 不传 s2c SYN，直接给 ACK，仍可核验
    client.post("/sessions/ack/directions/s2c/packets", json={"packets": [
        {"capture": 3, "seq": 555, "ack": 1005},
    ]})
    body = verify(client).json()
    assert body["isn"] == 1000
    assert body["acknowledged_gaps"] == [[3, 5]]


def test_pure_fin_gap_before_fin_verified(client):
    # 纯 SYN + 纯 FIN（fin 偏移 5，无任何数据）：FIN 前 [1,5) 全部是缺口
    client.post("/sessions", json={"session_id": "pf"})
    client.post("/sessions/pf/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 1000, "syn": True},
        {"capture": 2, "seq": 1005, "fin": True},
    ]})
    r = client.post("/sessions/pf/directions/c2s/revisions",
                    json={"expected_revision": 0})
    assert r.status_code == 201
    assert r.json()["gaps"] == [[1, 5]]
    assert r.json()["complete"] is False

    # cum=3 确认 [1,3)；SACK 确认 [4,5)；[3,4) 无依据
    client.post("/sessions/pf/directions/s2c/packets", json={"packets": [
        {"capture": 9, "seq": 8000, "ack": 1003,
         "sack": [{"left": 1004, "right": 1005}]},
    ]})
    body = verify(client, sid="pf").json()
    assert body["gaps"] == [[1, 5]]
    assert body["acknowledged_gaps"] == [[1, 3], [4, 5]]
    assert body["unacknowledged_gaps"] == [[3, 4]]


def test_syn_fin_alone_no_data_gap_when_fin_at_one(client):
    # SYN+FIN 同包、fin_pos=1：FIN 前无数据区间，无缺口
    client.post("/sessions", json={"session_id": "sf"})
    client.post("/sessions/sf/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 1000, "syn": True, "fin": True},
    ]})
    r = client.post("/sessions/sf/directions/c2s/revisions",
                    json={"expected_revision": 0})
    assert r.json()["gaps"] == []
    assert r.json()["complete"] is True
    body = verify(client, sid="sf").json()
    assert body["acknowledged_gaps"] == []
    assert body["unacknowledged_gaps"] == []


def test_direction_symmetric_s2c_target(client):
    # 目标方向为 s2c 时，确认证据取自 c2s
    client.post("/sessions", json={"session_id": "sym"})
    client.post("/sessions/sym/directions/s2c/packets", json={"packets": [
        {"capture": 1, "seq": 4000, "syn": True},
        {"capture": 2, "seq": 4001, "payload": b64(b"AB")},
        {"capture": 3, "seq": 4005, "payload": b64(b"CD")},
    ]})
    client.post("/sessions/sym/directions/s2c/revisions",
                json={"expected_revision": 0})
    client.post("/sessions/sym/directions/c2s/packets", json={"packets": [
        {"capture": 5, "seq": 200, "ack": 4004},
    ]})
    body = verify(client, sid="sym", d="s2c").json()
    assert body["direction"] == "s2c"
    assert body["isn"] == 4000
    assert body["acknowledged_gaps"] == [[3, 4]]
    assert body["unacknowledged_gaps"] == [[4, 5]]
