"""HTTP API 端到端测试。"""

import base64
import importlib
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "api.db")
    monkeypatch.setenv("DB_PATH", db_path)
    from app import main

    importlib.reload(main)
    main.DB_PATH = db_path
    with TestClient(main.app) as c:
        yield c


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def test_full_flow(client):
    # 创建会话（显式 ID）
    r = client.post("/sessions", json={"session_id": "demo"})
    assert r.status_code == 201
    assert r.json()["session_id"] == "demo"

    # 自动生成 ID
    r = client.post("/sessions", json={})
    assert r.status_code == 201
    assert r.json()["session_id"].startswith("s_")

    # 上传到不存在的会话 404
    r = client.post("/sessions/nope/directions/c2s/packets",
                    json={"packets": []})
    assert r.status_code in (404, 422)

    isn = 1000
    # 乱序上传：先数据后 SYN
    r = client.post("/sessions/demo/directions/c2s/packets", json={"packets": [
        {"capture": 2, "seq": isn + 1, "payload": b64(b"AB")},
    ]})
    assert r.status_code == 202

    r = client.post("/sessions/demo/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": isn, "syn": True},
        {"capture": 3, "seq": isn + 3, "payload": b64(b"CD")},
        {"capture": 4, "seq": isn + 5, "fin": True},
    ]})
    assert r.status_code == 202

    # 非法 base64 -> 422
    r = client.post("/sessions/demo/directions/c2s/packets", json={"packets": [
        {"capture": 9, "seq": 1, "payload": "@@notb64@@"},
    ]})
    assert r.status_code == 422

    # 首次发布，错误的期望修订号 -> 409，响应带当前修订号 0
    r = client.post("/sessions/demo/directions/c2s/revisions",
                    json={"expected_revision": 3})
    assert r.status_code == 409
    assert r.json()["detail"]["current_revision"] == 0

    # 正确发布
    r = client.post("/sessions/demo/directions/c2s/revisions",
                    json={"expected_revision": 0})
    assert r.status_code == 201
    body = r.json()
    assert body["revision"] == 1
    assert body["complete"] is True
    assert body["fin_pos"] == 5
    assert body["gaps"] == []

    # 已发布过，仍期望 0 -> 409，当前 1
    r = client.post("/sessions/demo/directions/c2s/revisions",
                    json={"expected_revision": 0})
    assert r.status_code == 409
    assert r.json()["detail"]["current_revision"] == 1

    # 报告
    r = client.get("/sessions/demo/directions/c2s/revisions/1/report")
    assert r.status_code == 200
    rep = r.json()
    assert rep["earliest_base64"] == b64(b"ABCD")
    assert rep["latest_base64"] == b64(b"ABCD")
    assert rep["page"]["done"] is True

    # latest 别名
    r = client.get("/sessions/demo/directions/c2s/revisions/latest")
    assert r.status_code == 200
    assert r.json()["revision"] == 1

    # 不存在修订 -> 404
    assert client.get(
        "/sessions/demo/directions/c2s/revisions/99/report"
    ).status_code == 404

    # 会话状态
    r = client.get("/sessions/demo")
    assert r.status_code == 200
    state = {d["direction"]: d for d in r.json()["directions"]}
    assert state["c2s"]["current_revision"] == 1
    assert state["c2s"]["syn_count"] == 1
    assert state["c2s"]["fin"] is True


def test_overlap_divergence_and_late_packet(client):
    client.post("/sessions", json={"session_id": "ov"})
    isn = 500
    client.post("/sessions/ov/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": isn, "syn": True},
        {"capture": 10, "seq": isn + 1, "payload": b64(b"AB")},
        {"capture": 20, "seq": isn + 2, "payload": b64(b"xC")},
    ]})
    client.post("/sessions/ov/directions/c2s/revisions",
                json={"expected_revision": 0})
    rep = client.get(
        "/sessions/ov/directions/c2s/revisions/1/report"
    ).json()
    assert base64.b64decode(rep["earliest_base64"]) == b"ABC"
    assert base64.b64decode(rep["latest_base64"]) == b"AxC"
    assert rep["divergence_intervals"] == [[2, 3]]
    assert rep["runs"][1]["earliest_source"]["capture"] == 10
    assert rep["runs"][1]["latest_source"]["capture"] == 20

    # 同捕获序号异内容 -> 409
    r = client.post("/sessions/ov/directions/c2s/packets", json={"packets": [
        {"capture": 10, "seq": isn + 1, "payload": b64(b"ZB")},
    ]})
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "capture_conflict"


def test_fin_conflict_422(client):
    client.post("/sessions", json={"session_id": "f"})
    client.post("/sessions/f/directions/s2c/packets", json={"packets": [
        {"capture": 1, "seq": 100, "syn": True},
        {"capture": 2, "seq": 104, "fin": True},
        {"capture": 3, "seq": 105, "fin": True},
    ]})
    r = client.post("/sessions/f/directions/s2c/revisions",
                    json={"expected_revision": 0})
    assert r.status_code == 422
    assert "FIN" in r.json()["detail"]["message"]


def test_pagination_over_gap(client):
    client.post("/sessions", json={"session_id": "g"})
    client.post("/sessions/g/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AB")},
        {"capture": 3, "seq": 10, "payload": b64(b"CD")},
    ]})
    client.post("/sessions/g/directions/c2s/revisions",
                json={"expected_revision": 0})
    p1 = client.get(
        "/sessions/g/directions/c2s/revisions/1/report",
        params={"max_bytes": 2},
    ).json()
    assert base64.b64decode(p1["earliest_base64"]) == b"AB"
    assert p1["page"]["next_offset"] == 3

    p2 = client.get(
        "/sessions/g/directions/c2s/revisions/1/report",
        params={"offset": 5},  # 落在缺口 [3,10) 内
    ).json()
    assert base64.b64decode(p2["earliest_base64"]) == b"CD"
    assert p2["runs"][0]["start"] == 10
    assert p2["gaps"] == [[3, 10]]
    assert p2["page"]["done"] is True
