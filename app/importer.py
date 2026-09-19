"""批量导入交接事件（UTF-8 CSV，两阶段：预览 -> 确认）。

流程与并发安全：

1. **预览**（``preview_import``）：解析上传的 CSV，逐行做字段级校验并给出
   逐行错误；同时把「现有事件 + 文件中的全部有效行」合并后跑一次审计，
   前端据此展示导入后审计结论的变化。预览阶段**不写库**，只返回一个
   无状态摘要令牌，内容绑定：

   * 样本 id；
   * 当前事件链的摘要（事件数 + 每条事件关键字段有序哈希）；
   * 文件内容 SHA-256、有效行数、生成时间，并用进程内随机密钥做 HMAC 签名。

2. **确认**（``commit_import``）：必须携带预览令牌。在 **单一事务**
   （``BEGIN IMMEDIATE`` 起手即拿写锁）内重新解析 / 校验文件，校验令牌签名、
   有效期、文件哈希，并再次计算当前事件链摘要与令牌绑定值比对——
   预览后该样本的事件链只要发生过任何增删改，摘要即不一致，整单拒绝并
   提示重新预览。全部行有效时才按文件顺序一次性写入（顺序分配 seq），
   随后刷新交接确认失效状态；任一环节失败则回滚，不允许部分落库。
"""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import secrets
from datetime import datetime, timedelta
from typing import Any, Optional
from sqlite3 import Connection

from .audit import build_audit
from .handovers import refresh_handover_validity
from .schemas import _normalize_time

# CSV 表头（去除空白后精确匹配）
EXPECTED_HEADERS = ["经手人", "开始时间", "结束时间", "备注"]
HEADER_LINE = ",".join(EXPECTED_HEADERS)

MAX_FILE_BYTES = 2 * 1024 * 1024  # 2MB
MAX_DATA_ROWS = 1000
CUSTODIAN_MAX = 64
NOTE_MAX = 512

# 令牌有效期（预览结果只在短时间内可被确认）
TOKEN_TTL = timedelta(minutes=30)

# 进程级签名密钥：不持久化，服务重启后旧令牌自然失效（提示重新预览即可）
_SECRET = secrets.token_bytes(32)


class ImportFileError(Exception):
    """文件级解析失败（无法产生逐行预览），由路由层转为 422。"""

    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ImportTokenError(Exception):
    """确认令牌无效 / 过期 / 与当前链路不匹配，由路由层转为 409。"""

    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- CSV 解析 ----------

def decode_csv(content: bytes) -> str:
    """解码上传内容：仅接受 UTF-8（兼容 Excel 另存的带 BOM 文件）。"""
    if len(content) > MAX_FILE_BYTES:
        raise ImportFileError(f"CSV 文件过大（上限 {MAX_FILE_BYTES // 1024 // 1024}MB）")
    try:
        # utf-8-sig：存在 BOM 时剥离，不存在时等同 utf-8
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImportFileError("文件不是有效的 UTF-8 编码，请将 CSV 另存为 UTF-8 后重新上传")


def parse_csv(text: str) -> list[dict[str, Any]]:
    """解析 CSV 文本为逐行结果。

    返回每行 ``{line, raw: {custodian,start_time,end_time,note}}`` 或
    ``{line, errors: [...]}``（列数错误等结构性问题）。不做字段级校验。
    """
    if not text.strip():
        raise ImportFileError("文件内容为空")

    reader = csv.reader(io.StringIO(text))
    try:
        rows = list(reader)
    except csv.Error as exc:
        raise ImportFileError(f"CSV 解析失败：{exc}")

    if not rows:
        raise ImportFileError("文件内容为空")

    header = [h.strip() for h in rows[0]]
    if header != EXPECTED_HEADERS:
        raise ImportFileError(
            "表头不正确，首行须为："
            + HEADER_LINE
            + "（可使用页面提供的模板下载）"
        )

    result: list[dict[str, Any]] = []
    for offset, cells in enumerate(rows[1:], start=2):
        # 完全空白的行（含零单元格）跳过；显式占位不算数据行
        if not cells or all(not str(c).strip() for c in cells):
            continue
        if len(cells) != len(EXPECTED_HEADERS):
            result.append(
                {
                    "line": offset,
                    "raw": {
                        "custodian": cells[0].strip() if len(cells) > 0 else "",
                        "start_time": cells[1].strip() if len(cells) > 1 else "",
                        "end_time": cells[2].strip() if len(cells) > 2 else "",
                        "note": cells[3].strip() if len(cells) > 3 else "",
                    },
                    "errors": [f"列数错误：应为 {len(EXPECTED_HEADERS)} 列（{HEADER_LINE}），实际 {len(cells)} 列"],
                }
            )
            continue
        custodian, start, end, note = (c.strip() for c in cells)
        result.append(
            {
                "line": offset,
                "raw": {
                    "custodian": custodian,
                    "start_time": start,
                    "end_time": end,
                    "note": note,
                },
            }
        )

    if not result:
        raise ImportFileError("文件中没有任何数据行（仅有表头）")
    if len(result) > MAX_DATA_ROWS:
        raise ImportFileError(f"数据行过多：单次最多导入 {MAX_DATA_ROWS} 行，当前 {len(result)} 行")
    return result


def validate_row(raw: dict[str, str]) -> dict[str, Any]:
    """单行字段级校验（与单条录入 ``EventCreate`` 同规则）。

    返回 ``{valid, errors, data}``，``data`` 为可直接写库的标准化值。
    """
    errors: list[str] = []
    custodian = raw["custodian"].strip()
    start_raw = raw["start_time"].strip()
    end_raw = raw["end_time"].strip()
    note = raw["note"].strip()

    if not custodian:
        errors.append("经手人不能为空")
    elif len(custodian) > CUSTODIAN_MAX:
        errors.append(f"经手人长度不能超过 {CUSTODIAN_MAX} 个字符")

    start_norm: Optional[str] = None
    end_norm: Optional[str] = None
    if not start_raw:
        errors.append("开始时间不能为空")
    else:
        try:
            start_norm = _normalize_time(start_raw, "开始时间")
        except ValueError:
            errors.append(f"开始时间格式应为 YYYY-MM-DD HH:MM:SS（当前值：{start_raw or '空'}）")

    if end_raw:
        try:
            end_norm = _normalize_time(end_raw, "结束时间")
        except ValueError:
            errors.append(f"结束时间格式应为 YYYY-MM-DD HH:MM:SS（当前值：{end_raw}）")

    if len(note) > NOTE_MAX:
        errors.append(f"备注长度不能超过 {NOTE_MAX} 个字符")

    if start_norm and end_norm and end_norm < start_norm:
        errors.append("结束时间不能早于开始时间")

    return {
        "valid": not errors,
        "errors": errors,
        "data": {
            "custodian": custodian,
            "start_time": start_norm,
            "end_time": end_norm,
            "note": note,
        },
    }


# ---------- 事件链摘要 ----------

def chain_digest(events: list[dict[str, Any]]) -> str:
    """当前事件链（含条数）的摘要；任何增删改都会改变。"""
    payload = [
        {
            "id": e["id"],
            "custodian": e["custodian"],
            "start_time": e["start_time"],
            "end_time": e["end_time"],
            "note": e["note"],
            "seq": e["seq"],
        }
        for e in sorted(events, key=lambda e: e["id"])
    ]
    raw = f"{len(payload)}|" + repr(payload)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _fetch_events(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, custodian, start_time, end_time, note, seq "
        "FROM events WHERE sample_id = ? ORDER BY id",
        (sample_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------- 摘要令牌（无状态，HMAC 签名） ----------

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue_token(sample_id: int, digest: str, file_sha256: str, valid_rows: int) -> str:
    body = (
        f"{sample_id}.{digest}.{file_sha256}.{valid_rows}."
        f"{int(datetime.now().timestamp())}"
    )
    body_b64 = _b64u(body.encode("utf-8"))
    sig = hmac.new(_SECRET, body_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{body_b64}.{_b64u(sig)}"


def _verify_signature(
    token: str,
) -> tuple[int, str, str, int]:
    """校验令牌签名与有效期，返回 (sample_id, 链路摘要, 文件 SHA-256, 有效行数)。"""
    parts = token.split(".")
    if len(parts) != 2:
        raise ImportTokenError("导入令牌格式无效，请重新预览后再确认")
    body_b64, sig_b64 = parts
    try:
        expected = hmac.new(_SECRET, body_b64.encode("ascii"), hashlib.sha256).digest()
        sig = _b64u_decode(sig_b64)
    except Exception:
        raise ImportTokenError("导入令牌格式无效，请重新预览后再确认")
    if not hmac.compare_digest(sig, expected):
        raise ImportTokenError("导入令牌校验失败，请重新预览后再确认")
    try:
        body = _b64u_decode(body_b64).decode("utf-8")
        sample_s, digest, file_sha256, rows_s, issued_s = body.split(".")
        sample_id = int(sample_s)
        valid_rows = int(rows_s)
        issued_at = datetime.fromtimestamp(int(issued_s))
    except Exception:
        raise ImportTokenError("导入令牌内容无效，请重新预览后再确认")
    if datetime.now() - issued_at > TOKEN_TTL:
        raise ImportTokenError("导入预览已超过有效期，请重新预览后再确认")
    return sample_id, digest, file_sha256, valid_rows


# ---------- 预览（不写库） ----------

def _projection(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """构造审计输入（统一补齐 build_audit 需要的字段）。"""
    return [
        {
            "id": e["id"],
            "custodian": e["custodian"],
            "start_time": e["start_time"],
            "end_time": e["end_time"],
            "note": e["note"],
            "seq": e["seq"],
        }
        for e in events
    ]


def build_preview(
    conn: Connection,
    sample_id: int,
    content: bytes,
) -> dict[str, Any]:
    """解析 CSV 并生成逐行校验结果 + 导入后审计变化预览（不写库）。"""
    text = decode_csv(content)
    parsed = parse_csv(text)

    existing = _fetch_events(conn, sample_id)
    current_audit = build_audit(_projection(existing))

    rows_view: list[dict[str, Any]] = []
    valid_count = 0
    error_count = 0
    base_seq = max((e["seq"] for e in existing), default=0)

    # 伪 id 仅供本次审计对导入行的排序/归属使用，绝不落库
    simulated = [dict(e) for e in existing]
    for idx, row in enumerate(parsed):
        line_no = row["line"]
        if row.get("errors"):
            errors = row["errors"]
            data = {
                "custodian": row["raw"]["custodian"],
                "start_time": row["raw"]["start_time"] or None,
                "end_time": row["raw"]["end_time"] or None,
                "note": row["raw"]["note"],
            }
            valid = False
        else:
            result = validate_row(row["raw"])
            errors = result["errors"]
            data = result["data"]
            valid = result["valid"]
        assigned_seq = base_seq + idx + 1
        rows_view.append(
            {
                "line": line_no,
                "seq": assigned_seq,
                "valid": valid,
                "errors": errors,
                "custodian": data["custodian"],
                "start_time": data["start_time"],
                "end_time": data["end_time"],
                "note": data["note"],
            }
        )
        if valid:
            valid_count += 1
            simulated.append(
                {
                    "id": -(idx + 1),
                    "custodian": data["custodian"],
                    "start_time": data["start_time"],
                    "end_time": data["end_time"],
                    "note": data["note"],
                    "seq": assigned_seq,
                }
            )
        else:
            error_count += 1

    # 全部行有效时才模拟「确认导入后」的审计结论；有错时不给出误导性结论
    simulated_audit = (
        build_audit(_projection(simulated)) if error_count == 0 else None
    )

    digest = chain_digest(existing)
    file_sha256 = hashlib.sha256(content).hexdigest()
    token = issue_token(sample_id, digest, file_sha256, valid_count)

    return {
        "sample_id": sample_id,
        "token": token,
        "file_sha256": file_sha256,
        "total_rows": len(parsed),
        "valid_rows": valid_count,
        "error_rows": error_count,
        "all_valid": error_count == 0,
        "token_expires_in_seconds": int(TOKEN_TTL.total_seconds()),
        "current_audit": {
            "status": current_audit["status"],
            "conclusion": current_audit["conclusion"],
            "summary": current_audit["summary"],
        },
        "preview_audit": (
            {
                "status": simulated_audit["status"],
                "conclusion": simulated_audit["conclusion"],
                "summary": simulated_audit["summary"],
                "findings": simulated_audit["findings"],
            }
            if simulated_audit
            else None
        ),
        "rows": rows_view,
    }


# ---------- 确认（单一事务） ----------

def commit_import(
    conn: Connection,
    sample_id: int,
    token: str,
    content: bytes,
) -> dict[str, Any]:
    """校验令牌与当前链路后，在单一事务内一次性写入全部行。

    任何失败都抛出异常且不写入任何事件（调用方不得提交）。
    """
    if not token or not str(token).strip():
        raise ImportTokenError("缺少导入令牌，请先重新预览后再确认")
    token = str(token).strip()

    # 1. 令牌签名 / 有效期 / 归属样本
    tok_sample, tok_digest, tok_file_sha, tok_rows = _verify_signature(token)
    if tok_sample != sample_id:
        raise ImportTokenError("导入令牌不属于当前样本，请重新预览后再确认")

    # 2. 文件须与预览时逐字节一致
    file_sha = hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(file_sha, tok_file_sha):
        raise ImportTokenError("上传文件与预览时不一致，请重新选择文件并预览")

    # 3. 重新解析并逐行校验（确认侧不信任前端）
    text = decode_csv(content)
    parsed = parse_csv(text)
    validated: list[dict[str, Any]] = []
    error_lines: list[int] = []
    for row in parsed:
        if row.get("errors"):
            error_lines.append(row["line"])
            continue
        result = validate_row(row["raw"])
        if not result["valid"]:
            error_lines.append(row["line"])
            continue
        validated.append(result["data"])
    if error_lines:
        raise ImportTokenError(
            "文件中仍存在未通过校验的行（第 "
            + "、".join(str(n) for n in error_lines[:10])
            + (" 等" if len(error_lines) > 10 else "")
            + " 行），请修正后重新预览"
        )
    if len(validated) != tok_rows or not validated:
        raise ImportTokenError("文件有效行数与预览结果不一致，请重新预览")

    # 4. 进入单一事务：起手即申请写锁，防止预览后/确认中并发写入。
    #    连接默认隔离级别下 sqlite3 模块会在 DML 前隐式补一个 BEGIN，
    #    与显式 BEGIN IMMEDIATE 冲突，这里临时切到 autocommit 自行管理事务。
    old_isolation = conn.isolation_level
    conn.isolation_level = None
    committed = False
    try:
        try:
            conn.execute("BEGIN IMMEDIATE")
        except Exception as exc:  # 数据库被锁定等
            raise ImportTokenError(f"数据库当前繁忙，请稍后重试（{exc}）")
        try:
            # 4.1 令牌绑定的链路摘要必须与当前完全一致（任何增删改都拒绝）
            existing = _fetch_events(conn, sample_id)
            if not hmac.compare_digest(chain_digest(existing), tok_digest):
                raise ImportTokenError(
                    "预览后该样本的交接事件链已发生增删改，导入为避免覆盖已中止；"
                    "请重新预览后再确认"
                )

            active_before = conn.execute(
                "SELECT COUNT(*) FROM handovers WHERE sample_id = ? AND status = 'active'",
                (sample_id,),
            ).fetchone()[0]

            # 4.2 按文件顺序一次性分配 seq 并写入
            base_seq = max((e["seq"] for e in existing), default=0)
            inserted_ids: list[int] = []
            for idx, data in enumerate(validated, start=1):
                cur = conn.execute(
                    "INSERT INTO events (sample_id, custodian, start_time, end_time, note, seq) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        sample_id,
                        data["custodian"],
                        data["start_time"],
                        data["end_time"],
                        data["note"],
                        base_seq + idx,
                    ),
                )
                inserted_ids.append(cur.lastrowid)

            # 4.3 新增事件改变相邻关系，原交接确认按规则失效
            refresh_handover_validity(conn, sample_id)
            active_after = conn.execute(
                "SELECT COUNT(*) FROM handovers WHERE sample_id = ? AND status = 'active'",
                (sample_id,),
            ).fetchone()[0]

            final_events = _fetch_events(conn, sample_id)
            final_audit = build_audit(_projection(final_events))
        except Exception:
            # 任一失败：回滚整个事务，绝不允许部分落库
            conn.rollback()
            raise

        # 事务内全部成功：提交。提交失败也意味着没有任何行落库
        conn.commit()
        committed = True
        return {
            "sample_id": sample_id,
            "imported_rows": len(inserted_ids),
            "event_ids": inserted_ids,
            "seq_from": base_seq + 1,
            "seq_to": base_seq + len(inserted_ids),
            "invalidated_handovers": max(0, active_before - active_after),
            "audit": {
                "status": final_audit["status"],
                "conclusion": final_audit["conclusion"],
                "summary": final_audit["summary"],
            },
        }
    finally:
        conn.isolation_level = old_isolation
        if not committed:
            conn.rollback()  # 防御：确保异常路径下事务已结束


# ---------- 模板下载 ----------

def template_csv() -> bytes:
    """CSV 导入模板内容（带 UTF-8 BOM，Windows Excel 双击不乱码）。"""
    lines = [
        HEADER_LINE,
        "张三（采集组）,2026-09-18 09:00:00,2026-09-18 10:00:00,现场采集并密封",
        "李四（运输组）,2026-09-18 10:00:00,2026-09-18 11:30:00,冷链运输 2-8℃",
        "王五（检测组）,2026-09-18 11:30:00,,结束时间留空表示当前仍在保管中",
    ]
    return ("\ufeff" + "\n".join(lines) + "\n").encode("utf-8")
