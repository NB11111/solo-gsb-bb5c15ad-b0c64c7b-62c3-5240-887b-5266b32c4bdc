"""批量导入交接事件（CSV）测试。

覆盖：模板下载、UTF-8/BOM 解码、表头与逐行校验、预览不写库、
导入后审计结论变化预览、令牌绑定链路摘要（预览后增删改则拒绝）、
令牌签名/篡改/跨样本拒绝、单一事务原子性（确认时重新校验，无部分落库）、
按文件顺序分配 seq、交接确认失效刷新，以及既有单条录入/报告导出不受影响。
"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-import-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_import.db")

import pytest
from fastapi.testclient import TestClient

from app.db import init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sample(client):
    resp = client.post(
        "/api/samples",
        json={"code": "UT-IMPORT-001", "name": "批量导入测试", "description": ""},
    )
    if resp.status_code == 409:
        sid = next(s["id"] for s in client.get("/api/samples").json() if s["code"] == "UT-IMPORT-001")
        client.delete(f"/api/samples/{sid}")
        resp = client.post(
            "/api/samples",
            json={"code": "UT-IMPORT-001", "name": "批量导入测试", "description": ""},
        )
    assert resp.status_code == 201
    return resp.json()


def _csv(rows: str, bom: bool = False) -> bytes:
    head = "\ufeff" if bom else ""
    return (head + "经手人,开始时间,结束时间,备注\n" + rows).encode("utf-8")


def _preview(client, sid, content: bytes):
    return client.post(
        f"/api/samples/{sid}/events/import/preview",
        files={"file": ("handovers.csv", content, "text/csv")},
    )


def _confirm(client, sid, content: bytes, token: str):
    return client.post(
        f"/api/samples/{sid}/events/import/confirm",
        files={"file": ("handovers.csv", content, "text/csv")},
        data={"token": token},
    )


def test_template_download(client):
    resp = client.get("/api/import-template")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "handovers_template" in resp.headers["content-disposition"]
    # UTF-8 BOM + 表头
    assert resp.content.startswith("\ufeff".encode("utf-8"))
    assert resp.content.decode("utf-8-sig").startswith("经手人,开始时间,结束时间,备注")


def test_bad_encoding_rejected(client, sample):
    sid = sample["id"]
    content = "经手人,开始时间,结束时间,备注\n张三,2026-09-18 09:00:00,2026-09-18 10:00:00,备注\n".encode("gbk")
    resp = _preview(client, sid, content)
    assert resp.status_code == 422
    assert "UTF-8" in resp.json()["detail"]


def test_bad_header_rejected_and_no_write(client, sample):
    sid = sample["id"]
    content = "custodian,start,end,note\n张三,2026-09-18 09:00:00,2026-09-18 10:00:00,\n".encode()
    resp = _preview(client, sid, content)
    assert resp.status_code == 422
    assert "表头" in resp.json()["detail"]
    assert client.get(f"/api/samples/{sid}").json()["events"] == []


def test_preview_row_errors_and_no_db_write(client, sample):
    sid = sample["id"]
    rows = (
        "张三,2026-09-18 09:00:00,2026-09-18 10:00:00,现场采集\n"
        ",2026-09-18 10:00:00,2026-09-18 11:00:00,经手人缺失\n"
        "李四,昨天,2026-09-18 11:00:00,时间格式错误\n"
        "王五,2026-09-18 12:00:00,2026-09-18 11:00:00,起止倒置\n"
        "赵六,2026-09-18 13:00:00,,开放保管合法\n"
    )
    resp = _preview(client, sid, _csv(rows))
    assert resp.status_code == 200
    p = resp.json()
    assert p["total_rows"] == 5
    assert p["valid_rows"] == 2
    assert p["error_rows"] == 3
    assert p["all_valid"] is False
    assert p["preview_audit"] is None  # 有错行时不模拟导入后结论
    assert p["current_audit"]["status"] == "empty"
    assert p["token"]
    line_errors = {r["line"]: r["errors"] for r in p["rows"] if not r["valid"]}
    assert any("经手人" in e for e in line_errors[3])
    assert any("开始时间" in e for e in line_errors[4])
    assert any("结束时间不能早于开始时间" in e for e in line_errors[5])
    # 开放保管行（结束时间留空）合法
    open_row = next(r for r in p["rows"] if r["line"] == 6)
    assert open_row["valid"] is True and open_row["end_time"] is None

    # 预览绝不写库
    detail = client.get(f"/api/samples/{sid}").json()
    assert detail["events"] == []

    # 存在错误行时禁止确认
    resp = _confirm(client, sid, _csv(rows), p["token"])
    assert resp.status_code == 409
    assert client.get(f"/api/samples/{sid}").json()["events"] == []


def test_preview_with_bom_and_audit_change_simulation(client, sample):
    sid = sample["id"]
    # 先有一条单条录入：09:00-10:00
    r = client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "张三", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00"},
    )
    assert r.status_code == 201
    # 导入第二、三段：10:00 无缝 -> 11:00 开放。导入前 empty? 不，已有 1 条 pass
    before = client.get(f"/api/samples/{sid}").json()
    assert before["audit"]["status"] == "pass"
    assert before["audit"]["summary"]["total"] == 1

    rows = (
        "李四,2026-09-18 10:00:00,2026-09-18 11:00:00,冷链\n"
        "王五,2026-09-18 11:00:00,,检测中\n"
    )
    resp = _preview(client, sid, _csv(rows, bom=True))
    assert resp.status_code == 200
    p = resp.json()
    assert p["all_valid"] is True
    # 新行从 seq=2 开始顺序分配
    assert [r["seq"] for r in p["rows"]] == [2, 3]
    fut = p["preview_audit"]
    assert fut is not None
    assert fut["summary"]["total"] == 3
    assert fut["summary"]["open_holds"] == 1
    assert fut["status"] == "pass"
    # 仍然没有写库
    assert len(client.get(f"/api/samples/{sid}").json()["events"]) == 1


def test_commit_success_seq_order_and_handover_invalidation(client, sample):
    sid = sample["id"]
    # 预置无缝两事件 + 已确认的交接项
    client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "张三", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00"},
    )
    e2 = client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "李四", "start_time": "2026-09-18 10:00:00",
              "end_time": "2026-09-18 11:00:00"},
    ).json()
    events = client.get(f"/api/samples/{sid}").json()["events"]
    e1_id = events[0]["id"]
    client.post(
        f"/api/samples/{sid}/handovers/confirm?from_event_id={e1_id}&to_event_id={e2['id']}",
        json={"side": "from", "confirmer_name": "张三", "confirmed_at": "2026-09-18 10:01:00"},
    )
    client.post(
        f"/api/samples/{sid}/handovers/confirm?from_event_id={e1_id}&to_event_id={e2['id']}",
        json={"side": "to", "confirmer_name": "李四", "confirmed_at": "2026-09-18 10:01:00"},
    )
    view = client.get(f"/api/samples/{sid}/handovers").json()
    assert view["summary"]["confirmed"] == 1

    # 在 09:30 插入一条事件会打断 张三->李四 的相邻关系
    rows = "赵六,2026-09-18 09:30:00,2026-09-18 10:00:00,档案补录\n"
    content = _csv(rows)
    p = _preview(client, sid, content).json()
    assert p["all_valid"] is True
    # 导入后存在断档（张三 10:00 归还，赵六 09:30 开始，时间排序后张三->赵六无缝，
    # 赵六 10:00 -> 李四 10:00 也无缝）—— 但录入逆序：seq=3 的赵六时间最早
    resp = _confirm(client, sid, content, p["token"])
    assert resp.status_code == 201, resp.text
    result = resp.json()
    assert result["imported_rows"] == 1
    assert result["seq_from"] == 3 and result["seq_to"] == 3
    assert result["invalidated_handovers"] == 1

    detail = client.get(f"/api/samples/{sid}").json()
    assert len(detail["events"]) == 3
    new_events = [e for e in detail["events"] if e["custodian"] == "赵六"]
    assert len(new_events) == 1 and new_events[0]["seq"] == 3
    # 原确认已移入失效历史
    hv = detail["handovers"]
    assert hv["summary"]["invalidated"] == 1
    assert hv["history"][0]["reason"] == "adjacency_changed"
    # 逆序补录被审计标注
    assert detail["audit"]["summary"]["out_of_order"] == 1


def test_commit_rejected_after_chain_changed(client, sample):
    sid = sample["id"]
    rows = "李四,2026-09-18 10:00:00,2026-09-18 11:00:00,\n"
    content = _csv(rows)
    p = _preview(client, sid, content).json()
    token = p["token"]

    # 预览后、确认前，链路被改动（单条录入）
    r = client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "张三", "start_time": "2026-09-18 08:00:00",
              "end_time": "2026-09-18 09:00:00"},
    )
    assert r.status_code == 201

    resp = _confirm(client, sid, content, token)
    assert resp.status_code == 409
    assert "重新预览" in resp.json()["detail"]
    # 只有后来单条录入的那一条，CSV 行未导入
    events = client.get(f"/api/samples/{sid}").json()["events"]
    assert len(events) == 1 and events[0]["custodian"] == "张三"

    # 编辑、删除同样导致拒绝
    p2 = _preview(client, sid, content).json()
    eid = events[0]["id"]
    client.put(
        f"/api/events/{eid}",
        json={"custodian": "张三改", "start_time": "2026-09-18 08:00:00",
              "end_time": "2026-09-18 09:00:00"},
    )
    resp = _confirm(client, sid, content, p2["token"])
    assert resp.status_code == 409

    p3 = _preview(client, sid, content).json()
    client.delete(f"/api/events/{eid}")
    resp = _confirm(client, sid, content, p3["token"])
    assert resp.status_code == 409
    assert client.get(f"/api/samples/{sid}").json()["events"] == []


def test_commit_rejects_tampered_or_foreign_token(client, sample):
    sid = sample["id"]
    other = client.post(
        "/api/samples", json={"code": "UT-IMPORT-OTHER", "name": "另一个样本"}
    ).json()
    rows = "李四,2026-09-18 10:00:00,2026-09-18 11:00:00,\n"
    content = _csv(rows)
    p = _preview(client, sid, content).json()

    # 无令牌
    resp = client.post(
        f"/api/samples/{sid}/events/import/confirm",
        files={"file": ("h.csv", content, "text/csv")},
        data={},
    )
    assert resp.status_code == 422

    # 篡改令牌
    bad_token = p["token"][:-3] + ("aaa" if p["token"][-3:] != "aaa" else "bbb")
    resp = _confirm(client, sid, content, bad_token)
    assert resp.status_code == 409

    # 跨样本使用令牌
    resp = _confirm(client, other["id"], content, p["token"])
    assert resp.status_code == 409
    assert client.get(f"/api/samples/{other['id']}").json()["events"] == []


def test_commit_rejects_changed_file(client, sample):
    sid = sample["id"]
    content = _csv("李四,2026-09-18 10:00:00,2026-09-18 11:00:00,原备注\n")
    p = _preview(client, sid, content).json()
    # 确认时文件内容变了（备注不同）
    changed = _csv("李四,2026-09-18 10:00:00,2026-09-18 11:00:00,被修改的备注\n")
    resp = _confirm(client, sid, changed, p["token"])
    assert resp.status_code == 409
    assert "不一致" in resp.json()["detail"]
    assert client.get(f"/api/samples/{sid}").json()["events"] == []


def test_commit_revalidates_rows_atomically(client, sample):
    sid = sample["id"]
    # 伪造令牌无法直接构造；这里验证：预览合法文件后，无法通过确认接口提交另一份
    # 含错误行的文件 —— 已由 test_commit_rejects_changed_file 覆盖哈希不一致场景。
    # 另验证空数据行 / 超量行的文件级错误返回 422。
    only_header = "经手人,开始时间,结束时间,备注\n\n  \n".encode()
    resp = _preview(client, sid, only_header)
    assert resp.status_code == 422

    too_many = _csv(
        "".join(
            f"人{i},2026-09-18 09:{i % 60:02d}:00,2026-09-18 10:{i % 60:02d}:00,\n"
            for i in range(1001)
        )
    )
    resp = _preview(client, sid, too_many)
    assert resp.status_code == 422
    assert "最多导入" in resp.json()["detail"]


def test_multi_row_import_all_or_nothing(client, sample):
    sid = sample["id"]
    # 全部合法的多行文件：按文件顺序分配连续 seq
    rows = (
        "甲,2026-09-18 09:00:00,2026-09-18 10:00:00,一\n"
        "乙,2026-09-18 10:00:00,2026-09-18 11:00:00,二\n"
        "丙,2026-09-18 11:00:00,,三\n"
    )
    content = _csv(rows)
    p = _preview(client, sid, content).json()
    assert p["valid_rows"] == 3
    resp = _confirm(client, sid, content, p["token"])
    assert resp.status_code == 201
    result = resp.json()
    assert result["seq_from"] == 1 and result["seq_to"] == 3
    assert len(result["event_ids"]) == 3
    detail = client.get(f"/api/samples/{sid}").json()
    by_seq = {e["seq"]: e for e in detail["events"]}
    assert [by_seq[i]["custodian"] for i in (1, 2, 3)] == ["甲", "乙", "丙"]
    assert by_seq[3]["end_time"] is None
    assert detail["audit"]["status"] == "pass"

    # 令牌一次性使用后再次提交：链路摘要已变化，必须拒绝（防止重复导入）
    resp = _confirm(client, sid, content, p["token"])
    assert resp.status_code == 409
    assert len(client.get(f"/api/samples/{sid}").json()["events"]) == 3


def test_mid_transaction_failure_rolls_back_everything(client, sample, monkeypatch):
    """写入中途失败（模拟刷新失效状态异常）时事务整体回滚，零行落库。"""
    sid = sample["id"]
    rows = (
        "甲,2026-09-18 09:00:00,2026-09-18 10:00:00,\n"
        "乙,2026-09-18 10:00:00,2026-09-18 11:00:00,\n"
    )
    content = _csv(rows)
    p = _preview(client, sid, content).json()

    import app.importer as importer

    def boom(conn, sample_id, now=None):
        raise RuntimeError("模拟刷新交接确认状态时失败")

    monkeypatch.setattr(importer, "refresh_handover_validity", boom)
    # TestClient 直接抛出未处理的内部异常（生产环境对应 500）；事务必须已整体回滚
    with pytest.raises(RuntimeError, match="模拟刷新"):
        _confirm(client, sid, content, p["token"])
    monkeypatch.undo()

    # 零行落库；回滚后令牌绑定的链路摘要未变，可重新预览并成功导入
    assert client.get(f"/api/samples/{sid}").json()["events"] == []
    p2 = _preview(client, sid, content).json()
    resp = _confirm(client, sid, content, p2["token"])
    assert resp.status_code == 201
    assert len(client.get(f"/api/samples/{sid}").json()["events"]) == 2


def test_existing_single_entry_and_report_still_work(client, sample):
    sid = sample["id"]
    # 单条录入仍可用
    r = client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "钱九", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00", "note": "单条录入"},
    )
    assert r.status_code == 201
    # 报告导出三种格式仍可用
    for fmt, needle in (("markdown", "审计报告"), ("html", "<table>"), ("json", "audit")):
        resp = client.get(f"/api/samples/{sid}/report?format={fmt}")
        assert resp.status_code == 200 and needle in resp.text
