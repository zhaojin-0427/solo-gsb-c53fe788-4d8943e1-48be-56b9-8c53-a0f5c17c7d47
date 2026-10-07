"""TCP 会话重组 HTTP API。"""

from __future__ import annotations

import base64
import binascii
import os
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from . import db, report, search, verify
from .reassembly import LIMIT, PublishRejected, RevisionConflict
from .report import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_RUNS,
    HARD_MAX_BYTES,
    HARD_MAX_RUNS,
)
from .schemas import (
    CreateSessionRequest,
    DirectionState,
    GapVerifyResponse,
    LocatePage,
    LocateRequest,
    PublishRequest,
    PublishResponse,
    ReportPage,
    RevisionMeta,
    SessionResponse,
    UploadRequest,
)

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.getcwd(), "data", "reassembly.db"))

@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = db.connect(DB_PATH)
    db.init_db(conn)
    conn.close()
    # 每个请求一条短连接，避免跨线程共享
    app.state.conn_factory = lambda: db.connect(DB_PATH)
    yield


app = FastAPI(
    title="TCP 会话重组 API",
    version="1.2.0",
    description=(
        "按会话/方向接收乱序报文，以唯一 SYN 为锚发布修订并分页重组，"
        "支持在指定修订的双份字节流上做字节特征定位，"
        "并可用对端 ACK/SACK 证据核验修订缺口。"
    ),
    lifespan=lifespan,
)


def get_conn(request: Request) -> sqlite3.Connection:
    return request.app.state.conn_factory()


@app.get("/health")
def health():
    return {"status": "ok"}


def _require_session(conn, session_id: str) -> None:
    if not db.session_exists(conn, session_id):
        raise HTTPException(status_code=404, detail=f"会话 {session_id} 不存在")


def _check_direction(direction: str) -> None:
    if direction not in db.VALID_DIRECTIONS:
        raise HTTPException(
            status_code=400, detail="direction 必须是 'c2s' 或 's2c'"
        )


def _resolve_revision(conn, session_id: str, direction: str, revision: str) -> int:
    """路径中的修订号：整数或 'latest'。方向无修订返回 404。"""
    if revision == "latest":
        rev = db.current_revision(conn, session_id, direction)
        if rev is None:
            raise HTTPException(404, detail="该方向尚无修订，先发布")
        return rev
    try:
        return int(revision)
    except ValueError:
        raise HTTPException(400, detail="revision 必须是整数或 'latest'")


def _decode_pattern(pattern_b64: str) -> bytes:
    """定位接口的模式必须是合法 Base64 且解码后非空，否则 422。"""
    try:
        pattern = base64.b64decode(pattern_b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_base64",
                "message": "pattern_base64 不是合法 Base64",
            },
        )
    if not pattern:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "empty_pattern",
                "message": "pattern_base64 解码后为空，模式必须非空",
            },
        )
    return pattern


@app.post("/sessions", response_model=SessionResponse, status_code=201)
def create_session(body: CreateSessionRequest, request: Request):
    conn = get_conn(request)
    try:
        session_id = body.session_id or f"s_{os.urandom(12).hex()}"
        existed = db.session_exists(conn, session_id)
        db.create_session(conn, session_id)
        return SessionResponse(session_id=session_id, created=not existed)
    finally:
        conn.close()


@app.get("/sessions")
def list_sessions(request: Request, limit: int = Query(default=100, ge=1, le=1000)):
    conn = get_conn(request)
    try:
        rows = conn.execute(
            "SELECT id FROM sessions ORDER BY created_at DESC, id LIMIT ?",
            (limit,),
        ).fetchall()
        return {"sessions": [r["id"] for r in rows]}
    finally:
        conn.close()


@app.get("/sessions/{session_id}")
def get_session(session_id: str, request: Request):
    conn = get_conn(request)
    try:
        _require_session(conn, session_id)
        directions = []
        for d in db.VALID_DIRECTIONS:
            cnt = conn.execute(
                "SELECT COUNT(*) c, SUM(syn) syns, SUM(fin) fins"
                " FROM packets WHERE session_id=? AND direction=?",
                (session_id, d),
            ).fetchone()
            directions.append(DirectionState(
                direction=d,
                current_revision=db.current_revision(conn, session_id, d) or 0,
                packet_count=cnt["c"] or 0,
                syn_count=cnt["syns"] or 0,
                fin=bool(cnt["fins"]),
            ))
        return {"session_id": session_id, "directions": directions}
    finally:
        conn.close()


@app.post("/sessions/{session_id}/directions/{direction}/packets", status_code=202)
def upload_packets(session_id: str, direction: str, body: UploadRequest,
                   request: Request):
    _check_direction(direction)
    conn = get_conn(request)
    try:
        _require_session(conn, session_id)

        decoded = []
        for p in body.packets:
            try:
                raw = base64.b64decode(p.payload, validate=True)
            except (binascii.Error, ValueError):
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "invalid_base64",
                        "capture": p.capture,
                        "message": f"capture={p.capture} 的 payload 不是合法 Base64",
                    },
                )
            sack = [list(b) for b in p.sack] if p.sack else None
            if sack and p.ack is None:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "sack_without_ack",
                        "capture": p.capture,
                        "message": f"capture={p.capture} 携带 SACK 块但缺少 ack 字段",
                    },
                )
            if sack and any(b[0] == b[1] for b in sack):
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "invalid_sack_block",
                        "capture": p.capture,
                        "message": f"capture={p.capture} 的 SACK 块为空块（left == right）",
                    },
                )
            decoded.append((p.capture, p.seq, 1 if p.syn else 0,
                            1 if p.fin else 0, raw, p.ack, sack))
        try:
            db.add_packets(conn, session_id, direction, decoded)
        except RevisionConflict as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "capture_conflict",
                    "current_revision": exc.current_revision,
                    "message": exc.message,
                },
            )
        return {
            "session_id": session_id,
            "direction": direction,
            "accepted": len(decoded),
            "current_revision": db.current_revision(conn, session_id, direction) or 0,
        }
    finally:
        conn.close()


@app.post(
    "/sessions/{session_id}/directions/{direction}/revisions",
    response_model=PublishResponse,
    status_code=201,
)
def publish(session_id: str, direction: str, body: PublishRequest,
            request: Request):
    _check_direction(direction)
    conn = get_conn(request)
    try:
        _require_session(conn, session_id)
        try:
            result = db.publish_revision(
                conn, session_id, direction, body.expected_revision
            )
        except RevisionConflict as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "revision_conflict",
                    "current_revision": exc.current_revision,
                    "message": exc.message,
                },
            )
        except PublishRejected as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "publish_rejected",
                    "current_revision": db.current_revision(
                        conn, session_id, direction
                    ) or 0,
                    "message": str(exc),
                },
            )
        return PublishResponse(
            session_id=session_id,
            direction=direction,
            revision=result["revision"],
            current_revision=result["revision"],
            isn=result["isn"],
            fin_pos=result["fin_pos"],
            complete=result["complete"],
            run_count=result["run_count"],
            gaps=result["gaps"],
        )
    finally:
        conn.close()


@app.get(
    "/sessions/{session_id}/directions/{direction}/revisions/{revision}",
    response_model=RevisionMeta,
)
def get_revision(session_id: str, direction: str, revision: str, request: Request):
    _check_direction(direction)
    conn = get_conn(request)
    try:
        _require_session(conn, session_id)
        rev = _resolve_revision(conn, session_id, direction, revision)
        meta = db.get_revision_meta(conn, session_id, direction, rev)
        if meta is None:
            raise HTTPException(404, detail=f"修订 {rev} 不存在")
        return RevisionMeta(**meta)
    finally:
        conn.close()


@app.get(
    "/sessions/{session_id}/directions/{direction}/revisions/{revision}/report",
    response_model=ReportPage,
)
def get_report(
    session_id: str,
    direction: str,
    revision: str,
    request: Request,
    offset: int = Query(default=1, ge=1, le=LIMIT),
    max_bytes: int = Query(default=DEFAULT_MAX_BYTES, ge=1, le=HARD_MAX_BYTES),
    max_runs: int = Query(default=DEFAULT_MAX_RUNS, ge=1, le=HARD_MAX_RUNS),
):
    _check_direction(direction)
    conn = get_conn(request)
    try:
        _require_session(conn, session_id)
        rev = _resolve_revision(conn, session_id, direction, revision)
        try:
            page = report.build_page(
                conn, session_id, direction, rev, offset, max_bytes, max_runs
            )
        except ValueError as exc:
            raise HTTPException(422, detail=str(exc))
        if page is None:
            raise HTTPException(404, detail=f"修订 {rev} 不存在")
        return page
    finally:
        conn.close()


@app.post(
    "/sessions/{session_id}/directions/{direction}/revisions/{revision}/locate",
    response_model=LocatePage,
)
def locate_pattern(session_id: str, direction: str, revision: str,
                   body: LocateRequest, request: Request):
    """字节特征定位：在指定修订的 earliest/latest 两份字节流中查找模式命中。"""
    _check_direction(direction)
    conn = get_conn(request)
    try:
        _require_session(conn, session_id)
        rev = _resolve_revision(conn, session_id, direction, revision)
        pattern = _decode_pattern(body.pattern_base64)
        page = search.locate_pattern(
            conn,
            session_id,
            direction,
            rev,
            pattern,
            body.offset,
            body.limit,
        )
        if page is None:
            raise HTTPException(404, detail=f"修订 {rev} 不存在")
        return page
    finally:
        conn.close()


@app.get(
    "/sessions/{session_id}/directions/{direction}/revisions/{revision}/ack-verify",
    response_model=GapVerifyResponse,
)
def verify_revision_gaps(session_id: str, direction: str, revision: str,
                         request: Request):
    """对端确认缺口核验：用反方向已入库的 ACK/SACK 核验该修订冻结的缺口。

    以目标修订的 ISN 为锚换算确认号；累计 ACK 覆盖 [1,确认偏移)，SACK 只覆盖
    各半开块。确认集合按请求时刻重算，晚到的确认证据会更新核验结果。
    """
    _check_direction(direction)
    conn = get_conn(request)
    try:
        _require_session(conn, session_id)
        rev = _resolve_revision(conn, session_id, direction, revision)
        result = verify.verify_gaps(conn, session_id, direction, rev)
        if result is None:
            raise HTTPException(404, detail=f"修订 {rev} 不存在")
        return result
    finally:
        conn.close()
