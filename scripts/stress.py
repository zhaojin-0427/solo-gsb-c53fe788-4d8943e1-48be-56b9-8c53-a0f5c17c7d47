"""规模与内存压测：

* 100,000 个报文，载荷总量 20 MiB（每包 ~200 字节）；
* 第 1 个包是 SYN；最后一个 FIN 落在接近 2^31 的位置，
  与数据之间形成近 2^31 字节的巨大缺口（缺口不占内存）；
* 报文按随机顺序（乱序）批量写入，发布修订；
* 校验：进程峰值 RSS < 256 MiB、缺口不被补零、两份重组分页内容正确。

用法：python3 scripts/stress.py [db 路径]
"""

from __future__ import annotations

import gc
import os
import random
import resource
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db, report  # noqa: E402

N_PACKETS = 100_000
PAYLOAD_PER_PACKET = 200          # 100_000 * 200 = 19.07 MiB
BATCH = 2_000
FIN_OFFSET = (1 << 31) - 1000     # 巨大缺口接近 2^31
ISN = 0xFFFFFFF0                  # 让部分早期数据跨越 32 位回绕点
MEMORY_LIMIT = 256 * 1024 * 1024


def rss_bytes() -> int:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024


def main() -> int:
    db_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/stress_reassembly.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    sid = "stress"
    direction = "c2s"
    conn = db.connect(db_path)
    db.init_db(conn)
    db.create_session(conn, sid)

    print(f"生成 {N_PACKETS} 个报文，载荷 {N_PACKETS * PAYLOAD_PER_PACKET / 2**20:.1f} MiB ...")
    t0 = time.time()
    packets = []
    # SYN
    packets.append((0, ISN, 1, 0, b""))
    # 数据报文：逻辑偏移 1..1+N*200；seq 32 位回绕
    total = 0
    for i in range(N_PACKETS - 2):
        cap = i + 1
        logical = 1 + i * PAYLOAD_PER_PACKET
        seq = (ISN + logical) & 0xFFFFFFFF
        # 每包内容可区分：写入 capture 号，便于抽样校验
        payload = (f"{cap:08d}".encode() * ((PAYLOAD_PER_PACKET // 8) + 1))[
            :PAYLOAD_PER_PACKET
        ]
        packets.append((cap, seq, 0, 0, payload))
        total += len(payload)
    # FIN 报文落在接近 2^31 的逻辑位置（巨大缺口）
    fin_logical = FIN_OFFSET
    packets.append((N_PACKETS - 1, (ISN + fin_logical) & 0xFFFFFFFF, 0, 1, b""))

    random.seed(42)
    random.shuffle(packets)
    print(f"准备耗时 {time.time() - t0:.1f}s，乱序后开始批量上传 ...")

    t0 = time.time()
    for i in range(0, len(packets), BATCH):
        db.add_packets(conn, sid, direction, packets[i:i + BATCH])
    upload_s = time.time() - t0
    print(f"上传完成：{upload_s:.1f}s，RSS={rss_bytes() / 2**20:.1f} MiB")

    gc.collect()
    t0 = time.time()
    res = db.publish_revision(conn, sid, direction, 0)
    publish_s = time.time() - t0
    print(
        f"发布修订 #{res['revision']}：{publish_s:.1f}s，run 数={res['run_count']}，"
        f"完整={res['complete']}，缺口数={len(res['gaps'])}，"
        f"缺口={res['gaps']}，RSS={rss_bytes() / 2**20:.1f} MiB"
    )
    assert res["complete"] is False, "存在巨大缺口时不应判定完整"
    assert res["gaps"] == [[1 + (N_PACKETS - 2) * PAYLOAD_PER_PACKET, FIN_OFFSET]]

    # 分页拉取两份重组，逐页校验、统计字节，确保内存受限
    t0 = time.time()
    offset = 1
    earliest_total = latest_total = 0
    pages = 0
    sample = {}
    while True:
        page = report.build_page(
            conn, sid, direction, res["revision"],
            offset=offset, max_bytes=256 * 1024, max_runs=5_000,
        )
        pages += 1
        eb = __import__("base64").b64decode(page["earliest_base64"])
        lb = __import__("base64").b64decode(page["latest_base64"])
        assert eb == lb, "无重叠分歧时两份重组应一致"
        earliest_total += len(eb)
        latest_total += len(lb)
        if pages <= 3 and eb:
            sample[pages] = eb[:8]
        nxt = page["page"]["next_offset"]
        if nxt is None:
            break
        offset = nxt
    read_s = time.time() - t0
    print(
        f"分页读取：{pages} 页 / {read_s:.1f}s，"
        f"earliest={earliest_total}B latest={latest_total}B，"
        f"RSS={rss_bytes() / 2**20:.1f} MiB"
    )
    assert earliest_total == latest_total == total
    gap_size = page["gaps"][0][1] - page["gaps"][0][0]
    print(f"缺口大小 = {gap_size} 字节（约 {gap_size / 2**30:.2f} * 2^30）")
    assert gap_size > (1 << 31) - 25_000_000

    # 缺口跳读：从缺口深处取页，应立即落到 FIN 前最后 run（无数据），不补零
    p_gap = report.build_page(
        conn, sid, direction, res["revision"],
        offset=(1 << 30), max_bytes=1024, max_runs=100,
    )
    assert p_gap["page"]["returned_bytes"] == 0
    assert p_gap["earliest_base64"] == ""
    assert p_gap["page"]["done"] is True

    peak = rss_bytes()
    print(f"峰值 RSS = {peak / 2**20:.1f} MiB（限制 256 MiB）")
    assert peak < MEMORY_LIMIT, f"峰值 RSS {peak} 超过 256 MiB"
    print("PASS")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
