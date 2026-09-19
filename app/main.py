"""FastAPI 入口：样本 / 交接事件 CRUD、审计、结论签署与报告导出。"""
from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlite3 import Connection

from .audit import build_audit
from .db import get_conn, init_db
from .handovers import (
    HandoverError,
    build_handover_view,
    confirm_handover,
    get_handover_record,
    refresh_handover_validity,
)
from .report import build_html, build_json, build_markdown
from .schemas import (
    EventCreate,
    HandoverConfirm,
    SampleCreate,
    SignoffCreate,
    SignoffRevoke,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # 启动时建表并写入演示数据（已初始化则跳过）
    init_db()
    yield


app = FastAPI(title="样本交接链路审计", version="1.0.0", lifespan=lifespan)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------- 样本 ----------

def _sample_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "code": row["code"],
        "name": row["name"],
        "description": row["description"],
        "created_at": row["created_at"],
    }


def _fetch_sample(conn: Connection, sample_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="样本不存在")
    return _sample_dict(row)


def _fetch_events(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE sample_id = ? ORDER BY id", (sample_id,)
    ).fetchall()
    return [
        {
            "id": r["id"],
            "custodian": r["custodian"],
            "start_time": r["start_time"],
            "end_time": r["end_time"],
            "note": r["note"],
            "seq": r["seq"],
        }
        for r in rows
    ]


@app.get("/api/samples")
def list_samples(conn: Connection = Depends(get_conn)) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM samples ORDER BY created_at DESC, id DESC").fetchall()
    samples = []
    for r in rows:
        count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE sample_id = ?", (r["id"],)
        ).fetchone()[0]
        d = _sample_dict(r)
        d["event_count"] = count
        samples.append(d)
    return samples


@app.post("/api/samples", status_code=201)
def create_sample(payload: SampleCreate, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    exists = conn.execute("SELECT 1 FROM samples WHERE code = ?", (payload.code,)).fetchone()
    if exists:
        raise HTTPException(status_code=409, detail=f"样本编号 {payload.code} 已存在")
    cur = conn.execute(
        "INSERT INTO samples (code, name, description, created_at) VALUES (?, ?, ?, ?)",
        (payload.code, payload.name, payload.description,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    return _fetch_sample(conn, cur.lastrowid)


@app.get("/api/samples/{sample_id}")
def get_sample(sample_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    sample = _fetch_sample(conn, sample_id)
    events = _fetch_events(conn, sample_id)
    audit = build_audit(events)
    return {
        "sample": sample,
        "events": events,
        "audit": audit,
        "signoffs": _list_signoffs(conn, sample_id),
        "handovers": build_handover_view(conn, sample_id),
    }


@app.delete("/api/samples/{sample_id}", status_code=204)
def delete_sample(sample_id: int, conn: Connection = Depends(get_conn)) -> Response:
    _fetch_sample(conn, sample_id)
    conn.execute("DELETE FROM samples WHERE id = ?", (sample_id,))
    conn.commit()
    return Response(status_code=204)


# ---------- 交接事件 ----------

@app.post("/api/samples/{sample_id}/events", status_code=201)
def add_event(
    sample_id: int, payload: EventCreate, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    _fetch_sample(conn, sample_id)
    seq = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE sample_id = ?", (sample_id,)
    ).fetchone()[0]
    cur = conn.execute(
        "INSERT INTO events (sample_id, custodian, start_time, end_time, note, seq) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (sample_id, payload.custodian, payload.start_time, payload.end_time, payload.note, seq),
    )
    # 新事件可能插入到某对相邻事件之间，原确认随之失效（记录保留）
    refresh_handover_validity(conn, sample_id)
    conn.commit()
    row = conn.execute("SELECT * FROM events WHERE id = ?", (cur.lastrowid,)).fetchone()
    return {"id": row["id"], "seq": row["seq"]}


@app.put("/api/events/{event_id}")
def update_event(event_id: int, payload: EventCreate, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="交接事件不存在")
    conn.execute(
        "UPDATE events SET custodian = ?, start_time = ?, end_time = ?, note = ? WHERE id = ?",
        (payload.custodian, payload.start_time, payload.end_time, payload.note, event_id),
    )
    # 绑定该事件关键字段的原确认保留为失效记录，需两侧重新确认
    refresh_handover_validity(conn, row["sample_id"])
    conn.commit()
    return {"id": event_id, "updated": True}


@app.delete("/api/events/{event_id}", status_code=204)
def delete_event(event_id: int, conn: Connection = Depends(get_conn)) -> Response:
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="交接事件不存在")
    sample_id = row["sample_id"]
    # 删除事件后，绑定它的原确认保留为失效记录（行与快照不删）
    conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
    refresh_handover_validity(conn, sample_id)
    conn.commit()
    return Response(status_code=204)


# ---------- 审计 ----------

@app.get("/api/samples/{sample_id}/audit")
def get_audit(sample_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    _fetch_sample(conn, sample_id)
    return build_audit(_fetch_events(conn, sample_id))


# ---------- 双向交接确认 ----------

@app.get("/api/samples/{sample_id}/handovers")
def list_handovers(sample_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    """交接项（审计排序相邻事件）当前状态 + 失效历史记录。"""
    _fetch_sample(conn, sample_id)
    return build_handover_view(conn, sample_id)


@app.post("/api/samples/{sample_id}/handovers/confirm", status_code=200)
def confirm_pair(
    sample_id: int,
    from_event_id: int,
    to_event_id: int,
    payload: HandoverConfirm,
    conn: Connection = Depends(get_conn),
) -> dict[str, Any]:
    """交出方（side=from）或接收方（side=to）填写姓名与确认时间。"""
    _fetch_sample(conn, sample_id)
    try:
        result = confirm_handover(
            conn,
            sample_id,
            from_event_id,
            to_event_id,
            payload.side,
            payload.confirmer_name,
            payload.confirmed_at,
        )
    except HandoverError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    conn.commit()
    return result


@app.get("/api/handovers/{handover_id}")
def get_handover(handover_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    """确认记录详情：双方确认信息、绑定的事件字段摘要、失效原因。"""
    try:
        return get_handover_record(conn, handover_id)
    except HandoverError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


# ---------- 结论签署（不可变快照） ----------

def _signoff_summary(row: Any) -> dict[str, Any]:
    """签署记录的列表/摘要视图：状态 + 从快照中提取的审计摘要。"""
    snap = json.loads(row["snapshot"])
    audit = snap.get("audit", {})
    return {
        "id": row["id"],
        "sample_id": row["sample_id"],
        "signer": row["signer"],
        "signed_at": row["signed_at"],
        "remark": row["remark"],
        "status": row["status"],
        "revoke_reason": row["revoke_reason"],
        "revoked_at": row["revoked_at"],
        "created_at": row["created_at"],
        "digest": row["digest"][:12],
        "audit_status": audit.get("status"),
        "conclusion": audit.get("conclusion"),
        "summary": audit.get("summary"),
        "event_count": len(snap.get("events", [])),
    }


def _list_signoffs(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM signoffs WHERE sample_id = ? ORDER BY id DESC", (sample_id,)
    ).fetchall()
    return [_signoff_summary(r) for r in rows]


def _fetch_signoff(conn: Connection, signoff_id: int) -> Any:
    row = conn.execute("SELECT * FROM signoffs WHERE id = ?", (signoff_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="签署记录不存在")
    return row


@app.post("/api/samples/{sample_id}/signoffs", status_code=201)
def create_signoff(
    sample_id: int, payload: SignoffCreate, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    """在当前审计结果上签署：保存样本 + 事件 + 审计发现的不可变快照。"""
    sample = _fetch_sample(conn, sample_id)
    events = _fetch_events(conn, sample_id)
    audit = build_audit(events)
    snapshot = {"sample": sample, "events": events, "audit": audit}
    raw = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.execute(
        "INSERT INTO signoffs (sample_id, signer, signed_at, remark, status, "
        "snapshot, digest, created_at) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
        (sample_id, payload.signer, payload.signed_at, payload.remark, raw, digest, now),
    )
    conn.commit()
    return _signoff_summary(_fetch_signoff(conn, cur.lastrowid))


@app.get("/api/samples/{sample_id}/signoffs")
def list_signoffs(sample_id: int, conn: Connection = Depends(get_conn)) -> list[dict[str, Any]]:
    _fetch_sample(conn, sample_id)
    return _list_signoffs(conn, sample_id)


@app.get("/api/signoffs/{signoff_id}")
def get_signoff(signoff_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    """快照详情：返回完整快照内容并现场校验完整性。"""
    row = _fetch_signoff(conn, signoff_id)
    detail = _signoff_summary(row)
    detail["digest"] = row["digest"]
    detail["snapshot"] = json.loads(row["snapshot"])
    detail["integrity_ok"] = (
        hashlib.sha256(row["snapshot"].encode("utf-8")).hexdigest() == row["digest"]
    )
    return detail


@app.post("/api/signoffs/{signoff_id}/revoke")
def revoke_signoff(
    signoff_id: int, payload: SignoffRevoke, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    """撤销签署：记录原因与时间，原快照保留不变。"""
    row = _fetch_signoff(conn, signoff_id)
    if row["status"] == "revoked":
        raise HTTPException(status_code=409, detail="该签署已撤销，请勿重复操作")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE signoffs SET status = 'revoked', revoke_reason = ?, revoked_at = ? WHERE id = ?",
        (payload.reason, now, signoff_id),
    )
    conn.commit()
    return _signoff_summary(_fetch_signoff(conn, signoff_id))


# ---------- 报告导出 ----------

def _safe_filename(code: str, ext: str) -> str:
    stem = re.sub(r"[^\w一-鿿-]+", "_", code).strip("_") or "sample"
    return f"audit_report_{stem}.{ext}"


@app.get("/api/samples/{sample_id}/report")
def export_report(
    sample_id: int,
    format: str = Query("markdown", pattern="^(markdown|html|json)$"),
    conn: Connection = Depends(get_conn),
):
    sample = _fetch_sample(conn, sample_id)
    audit = build_audit(_fetch_events(conn, sample_id))
    signoffs = _list_signoffs(conn, sample_id)
    handovers = build_handover_view(conn, sample_id)

    if format == "markdown":
        body = build_markdown(sample, audit, signoffs, handovers)
        headers = {"Content-Disposition": f'attachment; filename="{_safe_filename(sample["code"], "md")}"'}
        return PlainTextResponse(content=body, media_type="text/markdown; charset=utf-8", headers=headers)
    if format == "html":
        body = build_html(sample, audit, signoffs, handovers)
        headers = {"Content-Disposition": f'attachment; filename="{_safe_filename(sample["code"], "html")}"'}
        return HTMLResponse(content=body, media_type="text/html; charset=utf-8", headers=headers)

    body = build_json(sample, audit, signoffs, handovers)
    headers = {"Content-Disposition": f'attachment; filename="{_safe_filename(sample["code"], "json")}"'}
    return Response(content=body, media_type="application/json; charset=utf-8", headers=headers)


# ---------- 前端静态页（挂在最后，避免吞掉 API 路由） ----------

app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
