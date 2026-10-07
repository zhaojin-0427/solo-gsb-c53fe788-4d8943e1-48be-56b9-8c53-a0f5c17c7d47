"""字节特征定位（/locate）测试：跨 run 命中、缺口截断、双侧归并、
重叠命中、分页、跨读取窗口、修订不可变、422/404。"""

import base64
import importlib

import pytest
from fastapi.testclient import TestClient

from app import search


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "locate.db")
    monkeypatch.setenv("DB_PATH", db_path)
    from app import main

    importlib.reload(main)
    main.DB_PATH = db_path
    with TestClient(main.app) as c:
        yield c


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def locate(client, sid, rev, pattern, offset=1, limit=100, direction="c2s"):
    body = {"pattern_base64": b64(pattern), "offset": offset, "limit": limit}
    return client.post(
        f"/sessions/{sid}/directions/{direction}/revisions/{rev}/locate",
        json=body,
    )


def publish(client, sid, expected, direction="c2s"):
    return client.post(
        f"/sessions/{sid}/directions/{direction}/revisions",
        json={"expected_revision": expected},
    )


def packets(client, sid, ps, direction="c2s"):
    return client.post(
        f"/sessions/{sid}/directions/{direction}/packets",
        json={"packets": ps},
    )


def test_cross_run_hit_and_gap_truncation(client):
    # run1 [1,3)="AB"，run2 [3,6)="CDE" 相邻，run3 [8,11)="FGH"，缺口 [6,8)
    client.post("/sessions", json={"session_id": "g"})
    packets(client, "g", [
        {"capture": 1, "seq": 1000, "syn": True},
        {"capture": 2, "seq": 1001, "payload": b64(b"AB")},
        {"capture": 3, "seq": 1003, "payload": b64(b"CDE")},
        {"capture": 4, "seq": 1008, "payload": b64(b"FGH")},
    ])
    publish(client, "g", 0)

    # 跨相邻 run 命中：BC（起点 2）、CDE（起点 3）、DE（4）
    assert locate(client, "g", 1, b"BC").json()["hits"] == [
        {"offset": 2, "category": "both"}
    ]
    assert locate(client, "g", 1, b"CDE").json()["hits"] == [
        {"offset": 3, "category": "both"}
    ]
    # 缺口两侧绝不能拼接：EF（E 在偏移 5，F 在偏移 8，中间是缺口）
    assert locate(client, "g", 1, b"EF").json()["hits"] == []
    # 缺口后的正常命中
    assert locate(client, "g", 1, b"GH").json()["hits"] == [
        {"offset": 9, "category": "both"}
    ]


def test_hit_categories_dual_side_merge(client):
    # earliest=ABC，latest=AxC：偏移 2 两份不同
    client.post("/sessions", json={"session_id": "o"})
    packets(client, "o", [
        {"capture": 1, "seq": 500, "syn": True},
        {"capture": 10, "seq": 501, "payload": b64(b"AB")},
        {"capture": 20, "seq": 502, "payload": b64(b"xC")},
    ])
    publish(client, "o", 0)

    assert locate(client, "o", 1, b"AB").json()["hits"] == [
        {"offset": 1, "category": "earliest_only"}
    ]
    assert locate(client, "o", 1, b"Ax").json()["hits"] == [
        {"offset": 1, "category": "latest_only"}
    ]
    assert locate(client, "o", 1, b"BC").json()["hits"] == [
        {"offset": 2, "category": "earliest_only"}
    ]
    assert locate(client, "o", 1, b"xC").json()["hits"] == [
        {"offset": 2, "category": "latest_only"}
    ]
    # 同起点双侧归并为一条 both（C 在两份里一致）
    assert locate(client, "o", 1, b"C").json()["hits"] == [
        {"offset": 3, "category": "both"}
    ]


def test_overlapping_matches_allowed(client):
    client.post("/sessions", json={"session_id": "r"})
    packets(client, "r", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"aaaaa")},
    ])
    publish(client, "r", 0)
    offsets = [h["offset"] for h in locate(client, "r", 1, b"aa").json()["hits"]]
    assert offsets == [1, 2, 3, 4]


def test_pagination_chain(client):
    client.post("/sessions", json={"session_id": "p"})
    packets(client, "p", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"aaaaa")},
    ])
    publish(client, "p", 0)

    r = locate(client, "p", 1, b"aa", limit=2)
    j = r.json()
    assert [h["offset"] for h in j["hits"]] == [1, 2]
    assert j["next_offset"] == 3
    assert j["done"] is False

    r = locate(client, "p", 1, b"aa", offset=j["next_offset"], limit=2)
    j = r.json()
    assert [h["offset"] for h in j["hits"]] == [3, 4]
    assert j["next_offset"] is None
    assert j["done"] is True

    # offset 过滤：只返回 >= offset 的命中
    j = locate(client, "p", 1, b"aa", offset=3).json()
    assert [h["offset"] for h in j["hits"]] == [3, 4]


def test_no_hits_empty_page(client):
    client.post("/sessions", json={"session_id": "z"})
    packets(client, "z", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"ABCD")},
    ])
    publish(client, "z", 0)
    j = locate(client, "z", 1, b"ZZ").json()
    assert j["hits"] == []
    assert j["next_offset"] is None
    assert j["done"] is True


def test_invalid_base64_and_empty_pattern_422(client):
    client.post("/sessions", json={"session_id": "e"})
    packets(client, "e", [{"capture": 1, "seq": 0, "syn": True}])
    publish(client, "e", 0)

    r = client.post(
        "/sessions/e/directions/c2s/revisions/1/locate",
        json={"pattern_base64": "@@not@@"},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_base64"

    r = client.post(
        "/sessions/e/directions/c2s/revisions/1/locate",
        json={"pattern_base64": ""},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "empty_pattern"

    # limit 必须是正整数
    r = client.post(
        "/sessions/e/directions/c2s/revisions/1/locate",
        json={"pattern_base64": b64(b"A"), "limit": 0},
    )
    assert r.status_code == 422


def test_unknown_revision_404(client):
    client.post("/sessions", json={"session_id": "u"})
    packets(client, "u", [{"capture": 1, "seq": 0, "syn": True}])
    publish(client, "u", 0)
    r = client.post(
        "/sessions/u/directions/c2s/revisions/9/locate",
        json={"pattern_base64": b64(b"A")},
    )
    assert r.status_code == 404
    # 未知会话 404
    assert client.post(
        "/sessions/nope/directions/c2s/revisions/1/locate",
        json={"pattern_base64": b64(b"A")},
    ).status_code == 404


def test_latest_alias(client):
    client.post("/sessions", json={"session_id": "l"})
    packets(client, "l", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AB")},
    ])
    publish(client, "l", 0)
    r = client.post(
        "/sessions/l/directions/c2s/revisions/latest/locate",
        json={"pattern_base64": b64(b"AB")},
    )
    assert r.status_code == 200
    assert r.json()["revision"] == 1


def test_old_revision_hits_immutable_after_late_packet(client):
    client.post("/sessions", json={"session_id": "i"})
    packets(client, "i", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 10, "seq": 1, "payload": b64(b"AB")},
    ])
    publish(client, "i", 0)  # rev1: earliest=latest=AB
    assert locate(client, "i", 1, b"AB").json()["hits"] == [
        {"offset": 1, "category": "both"}
    ]

    # 晚到、capture 更小的报文：earliest 翻转为 xB，发布修订 2
    packets(client, "i", [{"capture": 5, "seq": 1, "payload": b64(b"xB")}])
    publish(client, "i", 1)

    # 旧修订命中不变
    assert locate(client, "i", 1, b"AB").json()["hits"] == [
        {"offset": 1, "category": "both"}
    ]
    # 新修订：AB 只在 latest，xB 只在 earliest，B 两份都有
    assert locate(client, "i", 2, b"AB").json()["hits"] == [
        {"offset": 1, "category": "latest_only"}
    ]
    assert locate(client, "i", 2, b"xB").json()["hits"] == [
        {"offset": 1, "category": "earliest_only"}
    ]
    assert locate(client, "i", 2, b"B").json()["hits"] == [
        {"offset": 2, "category": "both"}
    ]


def test_match_straddles_read_window_boundary(client):
    # 模式整体横跨 64 KiB 读取窗口边界（状态跨窗口保持）
    payload = b"." * (search.READ_WINDOW - 3) + b"ABCDE"
    client.post("/sessions", json={"session_id": "w"})
    packets(client, "w", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(payload)},
    ])
    publish(client, "w", 0)
    j = locate(client, "w", 1, b"ABCDE").json()
    assert j["hits"] == [{"offset": search.READ_WINDOW - 2,
                          "category": "both"}]


def test_cross_run_match_over_window_boundary(client):
    # run1 超过窗口若干倍、以 "ABCD" 收尾；run2 相邻以 "EFG" 开头：
    # 匹配既跨读取窗口又跨 run
    client.post("/sessions", json={"session_id": "wr"})
    packets(client, "wr", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"." * 1000 + b"ABCD")},
        {"capture": 3, "seq": 1005, "payload": b64(b"EFG" + b"." * 200000)},
    ])
    publish(client, "wr", 0)
    j = locate(client, "wr", 1, b"CDE").json()
    assert j["hits"] == [{"offset": 1003, "category": "both"}]
    j = locate(client, "wr", 1, b"BCDE").json()
    assert j["hits"] == [{"offset": 1002, "category": "both"}]
    # 缺口截断不受多窗口影响：制造不相邻 run
    client.post("/sessions", json={"session_id": "wg"})
    packets(client, "wg", [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"." * 200000 + b"AB")},
        {"capture": 3, "seq": 300000, "payload": b64(b"CD")},  # 缺口
    ])
    publish(client, "wg", 0)
    assert locate(client, "wg", 1, b"ABCD").json()["hits"] == []


def test_existing_publish_and_report_still_work(client):
    client.post("/sessions", json={"session_id": "x"})
    packets(client, "x", [
        {"capture": 1, "seq": 1000, "syn": True},
        {"capture": 2, "seq": 1001, "payload": b64(b"AB")},
        {"capture": 3, "seq": 1003, "payload": b64(b"CD")},
        {"capture": 4, "seq": 1005, "fin": True},
    ])
    r = publish(client, "x", 0)
    assert r.status_code == 201
    rep = client.get(
        "/sessions/x/directions/c2s/revisions/1/report"
    ).json()
    assert rep["earliest_base64"] == b64(b"ABCD")
