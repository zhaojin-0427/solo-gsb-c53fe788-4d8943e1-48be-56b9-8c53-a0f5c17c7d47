"""请求/响应模型。"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

Direction = Literal["c2s", "s2c"]

SeqNo = Annotated[int, Field(ge=0, le=0xFFFFFFFF, description="32 位 TCP 序号")]


class CreateSessionRequest(BaseModel):
    session_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="可选；不提供则服务器生成",
    )


class SessionResponse(BaseModel):
    session_id: str
    created: bool


class PacketIn(BaseModel):
    capture: int = Field(ge=0, description="捕获序号（本方向内唯一，越小越早捕获）")
    seq: int = Field(ge=0, le=0xFFFFFFFF, description="32 位 TCP 序列号")
    syn: bool = False
    fin: bool = False
    payload: str = Field(default="", description="Base64 编码的载荷（可为空字符串）")
    ack: SeqNo | None = Field(
        default=None,
        description="可选：32 位确认号（累计 ACK）；缺省表示报文不带 ACK",
    )
    sack: list[tuple[SeqNo, SeqNo]] | None = Field(
        default=None,
        description="可选：SACK 半开块 [[left,right),...]（32 位序号）；携带时必须有 ack",
    )


class UploadRequest(BaseModel):
    packets: list[PacketIn] = Field(min_length=1, max_length=20000)


class PublishRequest(BaseModel):
    expected_revision: int = Field(
        default=0, ge=0, description="期望的当前修订号；首次发布为 0"
    )


class PublishResponse(BaseModel):
    session_id: str
    direction: Direction
    revision: int
    current_revision: int
    isn: int
    fin_pos: int | None
    complete: bool
    run_count: int
    gaps: list[list[int]]


class RevisionMeta(BaseModel):
    revision: int
    isn: int
    fin_pos: int | None
    complete: bool
    run_count: int
    gaps: list[list[int]]
    created_at: str


class DirectionState(BaseModel):
    direction: Direction
    current_revision: int
    packet_count: int
    syn_count: int
    fin: bool


class RunView(BaseModel):
    index: int
    start: int
    end: int
    earliest_source: dict
    latest_source: dict
    divergent: bool


class ReportPage(BaseModel):
    session_id: str
    direction: Direction
    revision: int
    isn: int
    fin_pos: int | None
    complete: bool
    page: dict
    earliest_base64: str
    latest_base64: str
    runs: list[RunView]
    gaps: list[list[int]]
    divergence_intervals: list[list[int]]


class LocateRequest(BaseModel):
    pattern_base64: str = Field(
        description="非空标准 Base64 模式；解码后即要在两份字节流中定位的字节特征"
    )
    offset: int = Field(
        default=1, ge=1, le=1 << 31, description="分页起点（逻辑偏移），只返回 >= 该值的命中"
    )
    limit: int = Field(
        default=100, ge=1, le=10000, description="正整数页大小：本页最多返回的命中条数"
    )


class PatternHit(BaseModel):
    offset: int = Field(description="命中起点（模式首字节的逻辑偏移，1 起）")
    category: Literal["both", "earliest_only", "latest_only"] = Field(
        description="两份字节流均命中 / 仅最早捕获侧 / 仅最晚捕获侧"
    )


class LocatePage(BaseModel):
    session_id: str
    direction: Direction
    revision: int
    pattern_base64: str
    offset: int
    limit: int
    hits: list[PatternHit]
    next_offset: int | None
    done: bool


class VerifyEvidence(BaseModel):
    kind: Literal["ack", "sack"] = Field(
        description="累计 ACK 覆盖 [1,确认偏移) / SACK 半开块只覆盖块本身"
    )
    start: int = Field(description="确认区间起点（目标方向逻辑偏移，含）")
    end: int = Field(description="确认区间末端（不含）")
    packet_id: int = Field(description="来源报文内部 id（反方向）")
    capture: int = Field(description="来源报文捕获序号")


class GapVerifyResponse(BaseModel):
    session_id: str
    direction: Direction = Field(description="被核验的数据方向")
    revision: int
    isn: int
    fin_pos: int | None
    complete: bool
    evidence_direction: Direction = Field(description="确认证据来源方向（对端）")
    gaps: list[list[int]] = Field(description="该修订冻结的缺口区间 [start,end)")
    acknowledged_but_missing: list[list[int]] = Field(
        description="缺口中已被对端 ACK/SACK 确认、但本方向未捕获字节的区间"
    )
    no_evidence: list[list[int]] = Field(
        description="缺口中无任何确认依据的区间（不等于未送达，只是无证据）"
    )
    evidence: list[VerifyEvidence] = Field(
        description="请求时已入库、落在半序号窗口内的全部确认区间及来源引用"
    )
