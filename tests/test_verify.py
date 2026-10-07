"""对端确认缺口核验（/ack-verify）测试：

累计 ACK / SACK 半开块换算、缺口相交划分、并集去重、半序号窗口过滤、
422/404/409、晚到证据更新、旧修订缺口冻结、旧格式兼容。"""

import base64
import importlib

import pytest
from fastapi.testclient import TestClient


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


def packets(client, sid, ps, direction="c2s"):
    return client.post(
        f"/sessions/{sid}/directions/{direction}/packets",
        json={"packets": ps},
    )


def publish(client, sid, expected, direction="c2s"):
    return client.post(
        f"/sessions/{sid}/directions/{direction}/revisions",
        json={"expected_revision": expected},
    )


def verify(client, sid, rev, direction="c2s"):
    return client.get(
        f"/sessions/{sid}/directions/{direction}/revisions/{rev}/ack-verify"
    )


def make_gap_session(client, sid, isn=1000):
    """c2s：SYN + [1,3) "AB" + [10,12) "CD" => 缺口 [3,10)。"""
    client.post("/sessions", json={"session_id": sid})
    packets(client, sid, [
        {"capture": 1, "seq": isn, "syn": True},
        {"capture": 2, "seq": isn + 1, "payload": b64(b"AB")},
        {"capture": 3, "seq": isn + 10, "payload": b64(b"CD")},
    ])
    r = publish(client, sid, 0)
    assert r.status_code == 201
    assert r.json()["gaps"] == [[3, 10]]


def test_cumulative_ack_covers_gap_prefix(client):
    make_gap_session(client, "a")
    # 对端（s2c）累计 ACK：ack=isn+6 => 确认偏移 6 => 覆盖 [1,6)
    packets(client, "a", [{"capture": 1, "seq": 5000, "ack": 1006}], direction="s2c")

    r = verify(client, "a", 1)
    assert r.status_code == 200
    j = r.json()
    assert j["direction"] == "c2s"
    assert j["evidence_direction"] == "s2c"
    assert j["isn"] == 1000
    assert j["gaps"] == [[3, 10]]
    assert j["acknowledged_but_missing"] == [[3, 6]]
    assert j["no_evidence"] == [[6, 10]]
    acks = [e for e in j["evidence"] if e["kind"] == "ack"]
    assert [(e["start"], e["end"], e["capture"]) for e in acks] == [(1, 6, 1)]


def test_sack_block_does_not_act_as_cumulative(client):
    make_gap_session(client, "b")
    # ack=isn+3 只覆盖 [1,3)（不含缺口）；SACK 块 [isn+7, isn+10) 只覆盖 [7,10)。
    # 若误把 SACK 上界当累计确认，[3,10) 会被全部误判为已确认。
    packets(client, "b", [
        {"capture": 1, "seq": 5000, "ack": 1003, "sack": [[1007, 1010]]},
    ], direction="s2c")

    j = verify(client, "b", 1).json()
    assert j["acknowledged_but_missing"] == [[7, 10]]
    assert j["no_evidence"] == [[3, 7]]
    sacks = [e for e in j["evidence"] if e["kind"] == "sack"]
    assert [(e["start"], e["end"]) for e in sacks] == [(7, 10)]


def test_duplicate_reversed_ack_and_overlapping_sack_not_double_counted(client):
    make_gap_session(client, "c")
    packets(client, "c", [
        {"capture": 1, "seq": 5000, "ack": 1008},                    # [1,8)
        {"capture": 2, "seq": 5001, "ack": 1005},                    # 倒序 [1,5)
        {"capture": 3, "seq": 5002, "ack": 1008},                    # 重复
        {"capture": 4, "seq": 5003, "ack": 1004,
         "sack": [[1006, 1009], [1008, 1010]]},                      # 重叠块 [6,10)
    ], direction="s2c")

    j = verify(client, "c", 1).json()
    # 并集 [1,10)：缺口 [3,10) 全部被确认，且不重复计数
    assert j["acknowledged_but_missing"] == [[3, 10]]
    assert j["no_evidence"] == []


def test_out_of_half_sequence_window_ignored(client):
    make_gap_session(client, "d")
    limit = 1 << 31
    # ack 换算后 = 2^31 + 5，越出半序号窗口 => 忽略
    packets(client, "d", [
        {"capture": 1, "seq": 5000, "ack": (1000 + limit + 5) & 0xFFFFFFFF},
        # SACK 块右界越窗 => 整块忽略
        {"capture": 2, "seq": 5001, "ack": 1003,
         "sack": [[1005, (1000 + limit + 2) & 0xFFFFFFFF]]},
    ], direction="s2c")

    j = verify(client, "d", 1).json()
    assert j["acknowledged_but_missing"] == []
    assert j["no_evidence"] == [[3, 10]]
    # 只有合法的累计 ACK [1,3) 进入证据（它不覆盖缺口）
    assert [(e["kind"], e["start"], e["end"]) for e in j["evidence"]] == [
        ("ack", 1, 3)
    ]


def test_sack_without_ack_422(client):
    client.post("/sessions", json={"session_id": "e"})
    r = packets(client, "e", [
        {"capture": 1, "seq": 5000, "sack": [[1007, 1010]]},
    ], direction="s2c")
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "sack_without_ack"


def test_invalid_ack_sack_fields_422(client):
    client.post("/sessions", json={"session_id": "f"})
    # 空块（left == right）
    r = packets(client, "f", [
        {"capture": 1, "seq": 5000, "ack": 1003, "sack": [[1007, 1007]]},
    ], direction="s2c")
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_sack_block"
    # 块长度不为 2
    r = packets(client, "f", [
        {"capture": 1, "seq": 5000, "ack": 1003, "sack": [[1007, 1008, 1009]]},
    ], direction="s2c")
    assert r.status_code == 422
    # ack 超过 32 位
    r = packets(client, "f", [
        {"capture": 1, "seq": 5000, "ack": 1 << 32},
    ], direction="s2c")
    assert r.status_code == 422
    # SACK 元素为负
    r = packets(client, "f", [
        {"capture": 1, "seq": 5000, "ack": 1003, "sack": [[-1, 1008]]},
    ], direction="s2c")
    assert r.status_code == 422


def test_unknown_revision_and_session_404(client):
    make_gap_session(client, "g")
    assert verify(client, "g", 9).status_code == 404
    assert verify(client, "nope", 1).status_code == 404
    # latest 别名可用
    assert verify(client, "g", "latest").status_code == 200


def test_same_capture_different_ack_content_409(client):
    client.post("/sessions", json={"session_id": "h"})
    p = {"capture": 1, "seq": 5000, "ack": 1100}
    assert packets(client, "h", [p], direction="s2c").status_code == 202
    # 同内容幂等重传
    assert packets(client, "h", [p], direction="s2c").status_code == 202
    # 同捕获序号、确认号不同 => 409
    r = packets(client, "h", [{"capture": 1, "seq": 5000, "ack": 1200}],
                direction="s2c")
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "capture_conflict"
    # 同捕获序号、SACK 不同 => 409
    p2 = {"capture": 2, "seq": 5001, "ack": 1100, "sack": [[2000, 2010]]}
    assert packets(client, "h", [p2], direction="s2c").status_code == 202
    r = packets(client, "h", [
        {"capture": 2, "seq": 5001, "ack": 1100, "sack": [[2000, 2011]]},
    ], direction="s2c")
    assert r.status_code == 409
    # SACK 块顺序不同但集合相同 => 同一内容，幂等
    p3 = {"capture": 3, "seq": 5002, "ack": 1100,
          "sack": [[2000, 2010], [3000, 3010]]}
    assert packets(client, "h", [p3], direction="s2c").status_code == 202
    r = packets(client, "h", [
        {"capture": 3, "seq": 5002, "ack": 1100,
         "sack": [[3000, 3010], [2000, 2010]]},
    ], direction="s2c")
    assert r.status_code == 202


def test_late_evidence_updates_verification(client):
    make_gap_session(client, "i")
    j = verify(client, "i", 1).json()
    assert j["acknowledged_but_missing"] == []
    assert j["no_evidence"] == [[3, 10]]

    # 晚到的 ACK 证据：无需重新发布，下一次核验即更新
    packets(client, "i", [{"capture": 1, "seq": 5000, "ack": 1008}],
            direction="s2c")
    j = verify(client, "i", 1).json()
    assert j["acknowledged_but_missing"] == [[3, 8]]
    assert j["no_evidence"] == [[8, 10]]


def test_pure_fin_gap_scope_before_fin(client):
    # 纯 SYN/FIN 无载荷：核验范围是 FIN 之前的缺口
    client.post("/sessions", json={"session_id": "j"})
    packets(client, "j", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AB")},   # [1,3)
        {"capture": 3, "seq": 10, "fin": True},            # fin_pos=10，缺口 [3,10)
    ])
    r = publish(client, "j", 0)
    assert r.json()["fin_pos"] == 10
    assert r.json()["gaps"] == [[3, 10]]

    packets(client, "j", [{"capture": 1, "seq": 9000, "ack": 10}], direction="s2c")
    j = verify(client, "j", 1).json()
    assert j["fin_pos"] == 10
    assert j["gaps"] == [[3, 10]]
    assert j["acknowledged_but_missing"] == [[3, 10]]
    assert j["no_evidence"] == []


def test_old_revision_gaps_frozen_evidence_fresh(client):
    make_gap_session(client, "k")
    packets(client, "k", [{"capture": 1, "seq": 5000, "ack": 1008}],
            direction="s2c")
    # 晚到报文填补部分缺口，发布修订 2：缺口从 [3,10) 收缩为 [5,10)
    packets(client, "k", [{"capture": 4, "seq": 1003, "payload": b64(b"XY")}])
    r = publish(client, "k", 1)
    assert r.json()["gaps"] == [[5, 10]]

    # 旧修订缺口冻结不变，但确认集合按请求时重算（同一份证据作用于两版）
    j1 = verify(client, "k", 1).json()
    assert j1["gaps"] == [[3, 10]]
    assert j1["acknowledged_but_missing"] == [[3, 8]]
    assert j1["no_evidence"] == [[8, 10]]
    j2 = verify(client, "k", 2).json()
    assert j2["gaps"] == [[5, 10]]
    assert j2["acknowledged_but_missing"] == [[5, 8]]
    assert j2["no_evidence"] == [[8, 10]]


def test_sequence_rollover_ack_and_sack(client):
    # ISN 接近 2^32：ACK / SACK 换算跨 32 位回绕点
    client.post("/sessions", json={"session_id": "r"})
    isn = 0xFFFFFFFE
    packets(client, "r", [
        {"capture": 1, "seq": isn, "syn": True},
        {"capture": 2, "seq": 0xFFFFFFFF, "payload": b64(b"X")},  # 偏移 1
        {"capture": 3, "seq": 4, "payload": b64(b"Y")},           # 偏移 6
    ])
    r = publish(client, "r", 0)
    assert r.json()["gaps"] == [[2, 6]]

    packets(client, "r", [
        # ack=3 => 确认偏移 (3-isn) mod 2^32 = 5 => 覆盖 [1,5)
        {"capture": 1, "seq": 9000, "ack": 3},
        # SACK 块 [2,4) 相对偏移 [4,6)
        {"capture": 2, "seq": 9001, "ack": 3, "sack": [[2, 4]]},
    ], direction="s2c")
    j = verify(client, "r", 1).json()
    assert j["acknowledged_but_missing"] == [[2, 6]]
    assert j["no_evidence"] == []


def test_legacy_packets_without_ack_unaffected(client):
    # 旧格式报文（无 ack/sack 字段）：上传/发布/报告/定位不变，核验无证据
    client.post("/sessions", json={"session_id": "l"})
    packets(client, "l", [
        {"capture": 1, "seq": 1000, "syn": True},
        {"capture": 2, "seq": 1001, "payload": b64(b"AB")},
        {"capture": 3, "seq": 1010, "payload": b64(b"CD")},
    ])
    publish(client, "l", 0)
    rep = client.get("/sessions/l/directions/c2s/revisions/1/report").json()
    assert rep["gaps"] == [[3, 10]]
    loc = client.post(
        "/sessions/l/directions/c2s/revisions/1/locate",
        json={"pattern_base64": b64(b"CD")},
    ).json()
    assert loc["hits"] == [{"offset": 10, "category": "both"}]

    j = verify(client, "l", 1).json()
    assert j["gaps"] == [[3, 10]]
    assert j["acknowledged_but_missing"] == []
    assert j["no_evidence"] == [[3, 10]]
    assert j["evidence"] == []


def test_verify_opposite_direction_uses_c2s_evidence(client):
    # 核验 s2c 方向时，证据来自 c2s
    client.post("/sessions", json={"session_id": "m"})
    packets(client, "m", [
        {"capture": 1, "seq": 2000, "syn": True},
        {"capture": 2, "seq": 2001, "payload": b64(b"AB")},
        {"capture": 3, "seq": 2010, "payload": b64(b"CD")},
    ], direction="s2c")
    publish(client, "m", 0, direction="s2c")
    packets(client, "m", [{"capture": 9, "seq": 1, "ack": 2005}], direction="c2s")

    j = verify(client, "m", 1, direction="s2c").json()
    assert j["evidence_direction"] == "c2s"
    assert j["acknowledged_but_missing"] == [[3, 5]]
    assert j["no_evidence"] == [[5, 10]]
