"""请求/响应模型。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, conint, field_validator

Direction = Literal["c2s", "s2c"]


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


class SackBlock(BaseModel):
    left: int = Field(ge=0, le=0xFFFFFFFF, description="SACK 块左界（32 位序号，含）")
    right: int = Field(ge=0, le=0xFFFFFFFF, description="SACK 块右界（32 位序号，不含）")


class PacketIn(BaseModel):
    capture: int = Field(ge=0, description="捕获序号（本方向内唯一，越小越早捕获）")
    seq: int = Field(ge=0, le=0xFFFFFFFF, description="32 位 TCP 序列号")
    syn: bool = False
    fin: bool = False
    payload: str = Field(default="", description="Base64 编码的载荷（可为空字符串）")
    ack: int | None = Field(
        default=None,
        ge=0,
        le=0xFFFFFFFF,
        description="可选 32 位确认号；不提供即为旧格式报文",
    )
    sack: list[SackBlock] | None = Field(
        default=None,
        max_length=32,
        description="可选 SACK 半开块 [left,right)；接受 {left,right} 对象或 [left,right] 二元组，"
        "最多 32 块；带 SACK 必须带 ack",
    )

    @field_validator("sack", mode="before")
    @classmethod
    def _coerce_sack_pairs(cls, v):
        """允许每块写成 [left,right] 二元组（更接近 SACK 线上形态）。"""
        if v is None:
            return None
        return [
            {"left": b[0], "right": b[1]} if isinstance(b, (list, tuple)) else b
            for b in v
        ]


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


class AckEvidence(BaseModel):
    """单条对端确认证据的来源引用。"""

    packet_id: int
    capture: int
    ack: int | None = Field(description="该报文的 32 位确认号（无 ACK 字段时为 null）")


class CumulativeAckView(BaseModel):
    """半序号窗口内最大的累计确认（重复/倒序 ACK 不重复计数）。"""

    offset: int = Field(
        ge=0,
        le=(1 << 31),
        description="以目标修订 SYN 锚换算的累计确认偏移：覆盖 [1, offset)；0 表示未确认任何数据",
    )
    source: AckEvidence | None = Field(
        description="持有该最大确认号的报文来源（并列取最晚捕获）；无窗口内 ACK 时为 null"
    )


class SackBlockView(BaseModel):
    start: int = Field(ge=1, le=1 << 31, description="合并后 SACK 覆盖起点（逻辑偏移，含）")
    end: int = Field(ge=1, le=1 << 31, description="合并后 SACK 覆盖终点（逻辑偏移，不含）")
    sources: list[AckEvidence] = Field(description="覆盖该块的全部 SACK 证据来源")


class VerifyResponse(BaseModel):
    session_id: str
    direction: Direction
    revision: int
    isn: int = Field(description="目标修订冻结的 SYN 锚（ISN），确认号据此换算")
    fin_pos: int | None
    gaps: list[list[int]] = Field(description="随修订冻结的缺口区间 [start,end)")
    cumulative_ack: CumulativeAckView
    sack_blocks: list[SackBlockView] = Field(
        description="窗口内有效 SACK 的合并覆盖（已扣除累计确认 [1,cum)）；"
        "SACK 上界不当作累计确认"
    )
    acknowledged_gaps: list[list[int]] = Field(
        description="已确认但未捕获：缺口与确认覆盖的交集"
    )
    unacknowledged_gaps: list[list[int]] = Field(
        description="无确认依据：缺口与确认覆盖的差集；不等于未送达"
    )
    ignored_outside_window: int = Field(
        description="落在半序号窗口外而被忽略的 ACK/SACK 报文数"
    )
    note: str
