from __future__ import annotations

import os
import csv
import io
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from core.config import PROJECT_ROOT, load_config, project_path
from database.connection import connect_database, connect_readonly_database
from database.migrations import migrate
from database.repositories import (
    create_job,
    create_upload_job,
    get_job,
    get_status_values,
    latest_completed_job,
    list_device_locations,
    list_events,
    list_job_devices,
    list_jobs,
    list_live_or_window_devices,
    list_recent_events,
    update_device_metadata,
)
from services.upload_service import UploadError, UploadService
from workers.job_runner import run_csv_job, run_pcap_job


MONITOR_STATUS_KEYS = ("monitor_status", "monitor_instance_id", "monitor_job_id", "monitor_heartbeat", "monitor_degradation_reason")
WRITER_STATUS_KEYS = ("writer_status", "writer_heartbeat", "writer_queue_depth", "writer_retry_count", "writer_failed_batches", "writer_last_error")


class CreateJobRequest(BaseModel):
    source_type: str = Field(default="csv")
    source_path: str = Field(min_length=1, max_length=1024)


class UpdateDeviceRequest(BaseModel):
    device_name: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)


class CoreNodesRequest(BaseModel):
    gateway_ip: str | None = Field(default=None, max_length=100)
    gateway_name: str | None = Field(default="校園核心閘道 (Gateway)", max_length=255)
    firewall_ip: str | None = Field(default=None, max_length=100)
    firewall_name: str | None = Field(default="核心防火牆 (FortiGate)", max_length=255)
    core_switch_ip: str | None = Field(default=None, max_length=100)


class UpdateSwitchesYamlRequest(BaseModel):
    yaml_content: str | None = None
    switches: list[dict] | None = None


def _validate_source(source_path: str, source_type: str, allowed_root: Path = PROJECT_ROOT) -> Path:
    path = Path(source_path).expanduser().resolve()
    if not path.is_relative_to(Path(allowed_root).resolve()):
        # Spec 6.2 item 12: browsers must not make the server read arbitrary host files.
        raise HTTPException(status_code=400, detail="source must be inside the project directory")
    allowed = {"csv": {".csv"}, "pcap": {".pcap", ".pcapng"}, "pcapng": {".pcapng"}}
    if path.suffix.lower() not in allowed.get(source_type, set()):
        raise HTTPException(status_code=400, detail="source extension does not match source_type")
    if not path.is_file():
        raise HTTPException(status_code=400, detail="source CSV does not exist")
    max_size = int(os.getenv("DHCP_ANALYZER_MAX_SOURCE_BYTES", str(2 * 1024 * 1024 * 1024)))
    if path.stat().st_size > max_size:
        raise HTTPException(status_code=413, detail="source CSV exceeds configured size limit")
    return path


def _time_window(minutes: int, start_time: str | None, end_time: str | None) -> tuple[str, str]:
    if (start_time is None) != (end_time is None):
        raise HTTPException(status_code=400, detail="start_time and end_time must be provided together")
    if start_time and end_time:
        try:
            start = datetime.fromisoformat(start_time.replace("Z", "+00:00")).astimezone(timezone.utc)
            end = datetime.fromisoformat(end_time.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid ISO-8601 time range") from exc
        if end <= start:
            raise HTTPException(status_code=400, detail="end_time must be after start_time")
        if end - start > timedelta(days=7):
            raise HTTPException(status_code=400, detail="custom time range cannot exceed 7 days")
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)
    return (
        start.isoformat(timespec="seconds").replace("+00:00", "Z"),
        end.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def _seconds_since(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    try:
        moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - moment).total_seconds()))


def create_query_app(database_path: str = "data/dhcp_analyzer.db", route_prefix: str = "/api/v2", upload_root: str | Path | None = None, allowed_source_root: str | Path | None = None, config: dict | None = None) -> FastAPI:
    app = FastAPI(title="DHCP Analyzer Query API", version="2.0")
    settings = config or load_config()
    runtime = settings["runtime"]
    upload_cfg = settings["upload"]
    heartbeat_timeout = int(settings.get("monitor", {}).get("heartbeat_timeout", 15))
    max_queued_jobs = int(runtime.get("max_queued_jobs", 10))
    chunk_size = int(upload_cfg.get("chunk_size_kb", 1024)) * 1024
    executor = ThreadPoolExecutor(max_workers=max(1, int(runtime.get("max_workers", 1))), thread_name_prefix="dhcp-analysis")
    route_prefix = route_prefix.rstrip("/")
    source_root = Path(allowed_source_root).resolve() if allowed_source_root else PROJECT_ROOT
    uploads = UploadService(
        Path(upload_root) if upload_root else project_path(upload_cfg.get("root", "upload")),
        max_bytes=int(upload_cfg.get("max_file_size_mb", 2048)) * 1024 * 1024,
    )
    pending_jobs = {"count": 0}
    pending_lock = threading.Lock()

    # Initialize only a brand-new database. Existing databases are migrated
    # by deployment/monitor startup; GET requests must never migrate or change
    # WAL state while the live writer is committing batches.
    if not Path(database_path).exists():
        bootstrap = connect_database(database_path)
        try:
            migrate(bootstrap)
        finally:
            bootstrap.close()

    @app.exception_handler(sqlite3.OperationalError)
    async def sqlite_unavailable(_request: Request, exc: sqlite3.OperationalError):
        # Spec 20.3-C: busy/locked/unavailable DB is reported as 503, never as
        # a healthy or generic 500 response.
        busy = any(marker in str(exc).lower() for marker in ("locked", "busy"))
        return JSONResponse(
            status_code=503,
            headers={"Retry-After": "2"},
            content={"status": "error", "error": "database_busy" if busy else "database_unavailable", "message": "資料庫暫時無法服務，請稍後重試"},
        )

    def rows_to_dict(rows):
        return [dict(row) for row in rows]

    def submit_job(source_type: str, source_path: str, job_id: str) -> None:
        runner = run_csv_job if source_type == "csv" else run_pcap_job

        def run() -> None:
            try:
                runner(database_path, source_path, job_id)
            finally:
                with pending_lock:
                    pending_jobs["count"] -= 1

        with pending_lock:
            pending_jobs["count"] += 1
        executor.submit(run)

    def ensure_queue_capacity() -> None:
        with pending_lock:
            if pending_jobs["count"] >= max_queued_jobs:
                raise HTTPException(status_code=429, detail="analysis queue is full; retry later")

    @app.post(f"{route_prefix}/jobs", status_code=202)
    def create_analysis_job(request: CreateJobRequest):
        source_type = request.source_type.lower()
        if source_type not in {"csv", "pcap", "pcapng"}:
            raise HTTPException(status_code=400, detail="V2 supports CSV, PCAP, and PCAPNG jobs")
        source = _validate_source(request.source_path, source_type, source_root)
        ensure_queue_capacity()
        connection = connect_database(database_path)
        try:
            migrate(connection)
            job_id = create_job(connection, source_type, source.name, str(source))
        finally:
            connection.close()
        submit_job(source_type, str(source), job_id)
        return {"status": "accepted", "data": {"job_id": job_id, "status": "queued", "source_name": source.name}}

    @app.post(f"{route_prefix}/analysis/upload", status_code=202)
    async def upload_analysis_source(request: Request, filename: str = Query(min_length=1, max_length=255)):
        """Stream a raw request body (application/octet-stream) to disk.

        The HTTP request only stores the file and queues a job; parsing is
        done by the background worker (spec 10.8).
        """
        ensure_queue_capacity()

        async def chunks():
            buffer = bytearray()
            async for piece in request.stream():
                buffer.extend(piece)
                while len(buffer) >= chunk_size:
                    yield bytes(buffer[:chunk_size])
                    del buffer[:chunk_size]
            if buffer:
                yield bytes(buffer)

        try:
            stored = await uploads.store(filename, chunks())
        except UploadError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
        connection = connect_database(database_path)
        try:
            migrate(connection)
            job_id = create_upload_job(connection, stored.source_id, stored.source_type, stored.original_filename, str(stored.stored_path), stored.file_size, stored.file_hash)
        finally:
            connection.close()
        submit_job(stored.source_type, str(stored.stored_path), job_id)
        return {"status": "success", "data": {
            "job_id": job_id, "source_id": stored.source_id, "filename": stored.original_filename,
            "file_size": stored.file_size, "sha256": stored.file_hash, "source_type": stored.source_type, "status": "queued",
        }}

    @app.get(f"{route_prefix}/monitor/status")
    def monitor_status():
        connection = connect_readonly_database(database_path)
        try:
            values = get_status_values(connection, MONITOR_STATUS_KEYS + WRITER_STATUS_KEYS)
        finally:
            connection.close()

        def value(key):
            return values[key]["value"] if key in values else None

        heartbeat = value("monitor_heartbeat")
        seconds_ago = _seconds_since(heartbeat)
        reported = value("monitor_status")
        is_alive = seconds_ago is not None and seconds_ago < heartbeat_timeout and reported not in {"offline", "error"}
        if heartbeat is None:
            message = "尚無監控心跳紀錄"
        elif is_alive:
            message = "監控程序正常運作中"
        elif reported == "offline":
            message = "監控程序已正常停止"
        else:
            message = "監控心跳逾時"
        writer_heartbeat = value("writer_heartbeat")
        return {"status": "success", "data": {
            "is_alive": is_alive,
            "monitor_status": reported,
            "monitor_instance_id": value("monitor_instance_id"),
            "job_id": value("monitor_job_id"),
            "last_heartbeat": heartbeat,
            "seconds_ago": seconds_ago,
            "degradation_reason": value("monitor_degradation_reason"),
            "message": message,
            "writer": {
                "status": value("writer_status"),
                "last_heartbeat": writer_heartbeat,
                "seconds_ago": _seconds_since(writer_heartbeat),
                "queue_depth": value("writer_queue_depth"),
                "retry_count": value("writer_retry_count"),
                "failed_batches": value("writer_failed_batches"),
                "last_error": value("writer_last_error"),
            },
        }}

    @app.get(f"{route_prefix}/monitor/summary")
    def monitor_summary():
        connection = connect_readonly_database(database_path)
        try:
            job = connection.execute(
                "SELECT * FROM analysis_jobs WHERE source_type='live_monitor' ORDER BY created_at DESC, job_id DESC LIMIT 1"
            ).fetchone()
            if job is None:
                return {"status": "success", "data": None}
            stats = connection.execute("SELECT * FROM analysis_stats WHERE job_id=?", (job["job_id"],)).fetchone()
            today = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
            today_nak = connection.execute(
                "SELECT COUNT(*) FROM dhcp_events WHERE message_type='NAK' AND event_time >= ?", (today,)
            ).fetchone()[0]
        finally:
            connection.close()
        counters = json.loads(stats["counters_json"]) if stats and stats["counters_json"] else {}
        anomaly_keys = ("FLOODING", "DECLINE_DETECTED", "POSSIBLE_IP_CONFLICT", "CONFIRMED_IP_CONFLICT", "ABNORMAL_LEASE", "ROGUE_DHCP")
        return {"status": "success", "data": {
            "job_id": job["job_id"],
            "job_status": job["status"],
            "total_packets": stats["total_packets"] if stats else 0,
            "total_events": stats["total_events"] if stats else 0,
            "message_counts": {key: counters.get(key, 0) for key in ("DISCOVER", "OFFER", "REQUEST", "ACK", "NAK", "DECLINE", "INFORM", "RELEASE")},
            "today_nak": today_nak,
            "rogue_dhcp": counters.get("ROGUE_DHCP", 0),
            "anomaly_count": sum(counters.get(key, 0) for key in anomaly_keys),
            "silent_count": stats["silent_count"] if stats else 0,
            "dropped_in_memory_events": counters.get("DROPPED_IN_MEMORY_EVENTS", 0),
            "updated_at": stats["updated_at"] if stats else job["last_progress_at"],
        }}

    @app.get(f"{route_prefix}/jobs")
    def jobs(limit: int = Query(default=100, ge=1, le=500)):
        connection = connect_readonly_database(database_path)
        try:
            return {"status": "success", "data": rows_to_dict(list_jobs(connection, limit))}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/jobs/{{job_id}}")
    def job_detail(job_id: str):
        connection = connect_readonly_database(database_path)
        try:
            row = get_job(connection, job_id)
            if row is None:
                raise HTTPException(status_code=404, detail="job not found")
            stats = connection.execute("SELECT * FROM analysis_stats WHERE job_id=?", (job_id,)).fetchone()
            data = dict(row)
            data["stats"] = dict(stats) if stats else None
            return {"status": "success", "data": data}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/events")
    def events(job_id: str, limit: int = Query(default=100, ge=1, le=500), after_id: int | None = Query(default=None, ge=0), message_type: str | None = None):
        connection = connect_readonly_database(database_path)
        try:
            if get_job(connection, job_id) is None:
                raise HTTPException(status_code=404, detail="job not found")
            data = rows_to_dict(list_events(connection, job_id, limit, after_id, message_type))
            next_after_id = data[-1]["id"] if data else after_id
            return {"status": "success", "data": data, "next_after_id": next_after_id}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/events/recent")
    def recent_events(
        minutes: int = Query(default=5, ge=1, le=1440),
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = Query(default=1000, ge=1, le=2000),
        message_type: str | None = None,
    ):
        window_start, window_end = _time_window(minutes, start_time, end_time)
        connection = connect_readonly_database(database_path)
        try:
            data = rows_to_dict(connection_rows := list_recent_events(
                connection, window_start, window_end, limit, message_type
            ))
            return {
                "status": "success",
                "data": data,
                "window": {"start_time": window_start, "end_time": window_end},
                "truncated": len(connection_rows) >= limit,
            }
        finally:
            connection.close()

    @app.get(f"{route_prefix}/events/export")
    def export_events(
        minutes: int = Query(default=5, ge=1, le=1440),
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = Query(default=10000, ge=1, le=10000),
        message_type: str | None = None,
    ):
        window_start, window_end = _time_window(minutes, start_time, end_time)
        connection = connect_readonly_database(database_path)
        try:
            rows = list_recent_events(connection, window_start, window_end, limit, message_type)
        finally:
            connection.close()
        output = io.StringIO(newline="")
        fields = [
            "id", "job_id", "event_time", "source_type", "message_type", 
            "client_mac", "server_ip", "requested_ip", "assigned_ip", 
            "hostname", "relay_ip", "anomaly_type", "severity", "is_rogue"
        ]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row[field] for field in fields} for row in rows)
        filename = f"dhcp_events_{window_start.replace(':', '').replace('-', '')}_{window_end.replace(':', '').replace('-', '')}.csv"
        return StreamingResponse(
            iter([output.getvalue().encode("utf-8-sig")]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get(f"{route_prefix}/devices")
    def devices(
        job_id: str | None = None,
        minutes: int | None = Query(default=None, ge=1, le=1440),
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = Query(default=500, ge=1, le=500),
    ):
        """Retrieve device inventory.
        Priority: Normal (read-only mode, safe against database locks).
        Supports:
          1. Specific offline job (job_id)
          2. Time-window aggregation (minutes or start_time/end_time)
          3. Live network global inventory (fallback when no params)
        """
        connection = connect_readonly_database(database_path)
        try:
            # 1. 指定離線分析工作
            if job_id:
                if get_job(connection, job_id) is None:
                    raise HTTPException(status_code=404, detail="job not found")
                return {
                    "status": "success",
                    "source": "job",
                    "job_id": job_id,
                    "data": rows_to_dict(list_job_devices(connection, job_id, limit)),
                }

            # 2. 時間窗聚合分析
            if minutes is not None or (start_time and end_time):
                win_start, win_end = _time_window(minutes or 5, start_time, end_time)
                rows = list_live_or_window_devices(connection, win_start, win_end, limit)
                return {
                    "status": "success",
                    "source": "window",
                    "window": {"start_time": win_start, "end_time": win_end},
                    "data": rows_to_dict(rows),
                }

            # 3. 若有最近離線工作且尚未指定其他條件，優先檢查全網即時設備庫或離線工作
            # 優先回傳即時全網設備清冊
            live_rows = list_live_or_window_devices(connection, limit=limit)
            if live_rows:
                return {
                    "status": "success",
                    "source": "live",
                    "data": rows_to_dict(live_rows),
                }

            # 若即時庫尚無資料，嘗試回傳最近離線工作
            latest = latest_completed_job(connection)
            if latest:
                return {
                    "status": "success",
                    "source": "job",
                    "job_id": latest["job_id"],
                    "data": rows_to_dict(list_job_devices(connection, latest["job_id"], limit)),
                }

            return {"status": "success", "source": "empty", "job_id": None, "data": []}
        finally:
            connection.close()

    @app.patch(f"{route_prefix}/devices/{{mac}}")
    def update_device(mac: str, req: UpdateDeviceRequest):
        """Manually update device_name and location (spec 4.6)."""
        connection = connect_database(database_path)
        try:
            res = update_device_metadata(connection, mac, device_name=req.device_name, location=req.location)
            return {"status": "success", "data": res}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/locations")
    def locations(mac_address: str, limit: int = Query(default=100, ge=1, le=500)):
        connection = connect_readonly_database(database_path)
        try:
            return {"status": "success", "data": rows_to_dict(list_device_locations(connection, mac_address, limit))}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/topology/neighbors")
    def get_topology_neighbors():
        """Retrieve discovered switch LLDP/FDP neighbors."""
        connection = connect_readonly_database(database_path)
        try:
            cur = connection.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='switch_neighbors'")
            if not cur.fetchone():
                return {"status": "success", "data": []}
            rows = connection.execute(
                """SELECT n.*, s.sys_name as switch_name, s.management_ip as switch_ip
                   FROM switch_neighbors n
                   LEFT JOIN switches s ON n.switch_id = s.switch_id
                   ORDER BY n.observed_at DESC, n.id DESC LIMIT 500"""
            ).fetchall()
            return {"status": "success", "data": rows_to_dict(rows)}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/config/switches")
    def get_switches_config():
        """Retrieve switches.yaml content as structured JSON and raw YAML string."""
        import yaml
        sw_path = project_path("config/switches.yaml")
        if not os.path.exists(sw_path):
            return {"status": "success", "data": {"switches": [], "raw_yaml": ""}}
        with open(sw_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
        try:
            parsed = yaml.safe_load(raw_content) or {}
            switches = parsed.get("switches", [])
        except Exception:
            switches = []
        return {
            "status": "success",
            "data": {
                "switches": switches,
                "raw_yaml": raw_content
            }
        }

    @app.post(f"{route_prefix}/config/switches")
    def update_switches_config(req: UpdateSwitchesYamlRequest):
        """Update config/switches.yaml directly from web interface."""
        import yaml
        sw_path = project_path("config/switches.yaml")
        if req.yaml_content:
            # Validate valid YAML
            try:
                parsed = yaml.safe_load(req.yaml_content)
                if not isinstance(parsed, dict) or "switches" not in parsed:
                    raise HTTPException(status_code=400, detail="YAML 必須包含頂層 'switches' 清單")
            except yaml.YAMLError as e:
                raise HTTPException(status_code=400, detail=f"YAML 格式語法錯誤: {e}")
            with open(sw_path, "w", encoding="utf-8") as f:
                f.write(req.yaml_content)
        elif req.switches is not None:
            # Update switches list
            data = {"switches": req.switches}
            with open(sw_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        else:
            raise HTTPException(status_code=400, detail="必須提供 yaml_content 或 switches")

        return {"status": "success", "message": "switches.yaml 設定已成功儲存"}

    @app.get(f"{route_prefix}/topology/switches")
    def get_topology_switches():
        """Retrieve full switch list with enabled flags, poll statuses, FDB counts, and neighbor counts."""
        import yaml
        sw_path = project_path("config/switches.yaml")
        yaml_switches = {}
        if os.path.exists(sw_path):
            try:
                with open(sw_path, "r", encoding="utf-8") as f:
                    ydata = yaml.safe_load(f) or {}
                    for s in ydata.get("switches", []):
                        if s and s.get("management_ip"):
                            yaml_switches[s["management_ip"]] = s
            except Exception:
                pass

        connection = connect_readonly_database(database_path)
        try:
            cur = connection.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='switches'")
            if not cur.fetchone():
                return {"status": "success", "data": []}
            rows = connection.execute(
                """SELECT s.*,
                          (SELECT COUNT(*) FROM switch_fdb_current f WHERE f.switch_id = s.switch_id) as fdb_count,
                          (SELECT COUNT(*) FROM switch_neighbors n WHERE n.switch_id = s.switch_id) as neighbor_count
                   FROM switches s
                   ORDER BY s.management_ip ASC"""
            ).fetchall()
            result = []
            db_ips = set()
            for r in rows:
                d = dict(r)
                ip = d.get("management_ip")
                db_ips.add(ip)
                y_info = yaml_switches.get(ip, {})
                d["is_enabled"] = bool(y_info.get("enabled", True))
                result.append(d)

            # If any switch in yaml is not yet in DB, append with default SNMP_UNCONFIGURED / PENDING
            for ip, y in yaml_switches.items():
                if ip not in db_ips:
                    is_en = bool(y.get("enabled", True))
                    result.append({
                        "switch_id": ip,
                        "management_ip": ip,
                        "sys_name": y.get("name", ip),
                        "vendor": y.get("vendor", "Generic"),
                        "model": y.get("model", ""),
                        "sys_descr": None,
                        "last_poll_time": None,
                        "poll_status": "ONLINE_SNMP_OK" if is_en else "SNMP_UNCONFIGURED",
                        "fdb_count": 0,
                        "neighbor_count": 0,
                        "is_enabled": is_en,
                    })

            result.sort(key=lambda x: [int(p) if p.isdigit() else p for p in str(x.get("management_ip", "")).split(".")])
            return {"status": "success", "data": result}
        finally:
            connection.close()

    @app.get(f"{route_prefix}/topology/graph")
    def get_topology_graph():
        """Generate Vis.js compatible nodes and edges representing switch topology and health.
        - Root: Gateway (Level 1), with Firewall (Level 0) above if set.
        - Switches: Distributed horizontally at Level 2 and Level 3.
        - Edge styling by link speed/bandwidth:
          >= 10 Gbps: Green (#10B981), 7.5 px (max 0.2cm).
          1 Gbps ~ 10 Gbps: Orange (#F59E0B), 4.5 px.
          < 1 Gbps: Red (#EF4444), 2.0 px.
        """
        connection = connect_readonly_database(database_path)
        try:
            cur = connection.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='switches'")
            if not cur.fetchone():
                return {"status": "success", "data": {"nodes": [], "edges": []}}

            sw_rows = connection.execute(
                """SELECT s.*, 
                          (SELECT COUNT(*) FROM switch_fdb_current f WHERE f.switch_id = s.switch_id) as fdb_count,
                          (SELECT COUNT(*) FROM alerts a WHERE a.switch_id = s.switch_id AND a.status = 'OPEN') as alert_count
                   FROM switches s"""
            ).fetchall()

            # Load Core Nodes (Firewall & Gateway)
            cfg = load_config()
            net_cfg = cfg.get("network", {})
            fw_ip = net_cfg.get("firewall_ip")
            gw_ip = net_cfg.get("gateway_ip") or "192.69.1.254"  # Default Gateway if not specified
            core_sw_ip = net_cfg.get("core_switch_ip")

            # Load enabled switches from switches.yaml
            import yaml
            sw_path = project_path("config/switches.yaml")
            enabled_ips = set()
            if os.path.exists(sw_path):
                try:
                    with open(sw_path, "r", encoding="utf-8") as f:
                        ydata = yaml.safe_load(f) or {}
                        for s in ydata.get("switches", []):
                            if s and s.get("enabled", True):
                                enabled_ips.add(s.get("management_ip"))
                except Exception:
                    pass

            fw_id = "__FIREWALL__"
            gw_id = "__GATEWAY__"

            nodes = []
            color_map = {
                "ONLINE_SNMP_OK": {"background": "#10B981", "border": "#059669", "highlight": "#34D399"},
                "COMMUNITY_MISCONFIGURED": {"background": "#F59E0B", "border": "#D97706", "highlight": "#FBBF24"},
                "HOST_OFFLINE": {"background": "#EF4444", "border": "#DC2626", "highlight": "#F87171"},
                "SNMP_DEGRADED": {"background": "#F97316", "border": "#EA580C", "highlight": "#FB923C"},
                "SNMP_UNCONFIGURED": {"background": "#94A3B8", "border": "#64748B", "highlight": "#CBD5E1"},
            }

            # Helper for edge styling based on max link speed / bandwidth
            def get_edge_style(speed_bps: int, label_note: str = ""):
                # 0.2cm at 96 DPI is approx 7.56 px -> max 7.5 px
                if speed_bps >= 10_000_000_000:
                    return {
                        "color": {"color": "#10B981", "highlight": "#34D399"},
                        "width": 7.5,
                        "speed_label": "10 Gbps (光纖骨幹)" if not label_note else f"10G [{label_note}]",
                    }
                elif speed_bps >= 1_000_000_000:
                    return {
                        "color": {"color": "#F59E0B", "highlight": "#FBBF24"},
                        "width": 4.5,
                        "speed_label": "1 Gbps (Giga 鏈結)" if not label_note else f"1G [{label_note}]",
                    }
                else:
                    return {
                        "color": {"color": "#EF4444", "highlight": "#F87171"},
                        "width": 2.0,
                        "speed_label": "100 Mbps (低速/相容)" if not label_note else f"100M [{label_note}]",
                    }

            # Classify switches into Core (Level 2) and Edge/Distribution (Level 3)
            # Cisco 110, Aruba 102/104/106, or user-designated core_switch are Level 2
            core_switch_ids = set()
            for sw in sw_rows:
                sw_ip = sw["management_ip"] or sw["switch_id"]
                model_str = (sw["model"] or "").lower()
                sys_str = (sw["sys_name"] or "").lower()
                if core_sw_ip and sw_ip == core_sw_ip:
                    core_switch_ids.add(sw["switch_id"])
                elif "c3560" in model_str or "3810m" in model_str or "core" in sys_str:
                    core_switch_ids.add(sw["switch_id"])

            for sw in sw_rows:
                ip = sw["management_ip"] or sw["switch_id"]
                # Only include switches that are enabled: true or designated core switch in topology
                if enabled_ips and ip not in enabled_ips and sw["switch_id"] not in core_switch_ids:
                    continue

                status = sw["poll_status"] or "UNKNOWN"
                c = color_map.get(status, {"background": "#94A3B8", "border": "#64748B", "highlight": "#CBD5E1"})
                lbl_name = sw["sys_name"] or sw["switch_id"]
                ip = sw["management_ip"] or sw["switch_id"]
                vendor = sw["vendor"] or "Switch"
                fdb_cnt = sw["fdb_count"] or 0
                alert_cnt = sw["alert_count"] or 0
                is_core = sw["switch_id"] in core_switch_ids

                level = 2 if is_core else 3
                label = f"{lbl_name}\n({ip})\n[{vendor} / L{level}]"
                if alert_cnt > 0:
                    label += f"\n⚠️ 告警: {alert_cnt}"

                nodes.append({
                    "id": sw["switch_id"],
                    "label": label,
                    "title": f"交換器: {lbl_name}<br>IP: {ip}<br>廠牌: {vendor}<br>型號: {sw['model'] or 'N/A'}<br>階層: Level {level}<br>狀態: {status}<br>在線終端(FDB): {fdb_cnt}<br>未解決告警: {alert_cnt}",
                    "shape": "box",
                    "margin": 10,
                    "level": level,
                    "font": {"color": "#FFFFFF", "size": 13, "bold": True},
                    "color": c,
                    "poll_status": status,
                    "vendor": vendor,
                    "management_ip": ip,
                    "fdb_count": fdb_cnt,
                    "alert_count": alert_cnt,
                    "is_root": False,
                })

            # Edges from switch_neighbors with bandwidth evaluation
            edges = []
            seen_edges = set()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='switch_neighbors'")
            if cur.fetchone():
                nb_rows = connection.execute(
                    """SELECT n.*, s1.management_ip as local_ip, s2.switch_id as target_switch_id
                       FROM switch_neighbors n
                       JOIN switches s1 ON n.switch_id = s1.switch_id
                       LEFT JOIN switches s2 ON n.remote_mgmt_ip = s2.management_ip
                       ORDER BY n.id ASC"""
                ).fetchall()

                for nb in nb_rows:
                    target_id = nb["target_switch_id"]
                    if not target_id and nb["remote_mgmt_ip"]:
                        match = next((s["switch_id"] for s in sw_rows if s["management_ip"] == nb["remote_mgmt_ip"]), None)
                        target_id = match

                    if target_id and target_id in {s["switch_id"] for s in sw_rows}:
                        pair = tuple(sorted([nb["switch_id"], target_id]))
                        if pair not in seen_edges and nb["switch_id"] != target_id:
                            seen_edges.add(pair)
                            proto = nb["protocol"] or "LLDP"
                            l_port = str(nb["local_if_index"] or "?")
                            r_port = str(nb["remote_port_id"] or "?")

                            # Determine link speed (10G vs 1G vs 100M)
                            # Ports like 132/55/SFP+ or 1/3/4 indicate 10G uplink on Ruckus/Aruba
                            is_10g = any(kw in r_port.lower() or kw in l_port.lower() for kw in ("1/3/", "10g", "sfp+", "xg", "ten", "132", "55"))
                            speed_bps = 10_000_000_000 if is_10g else 1_000_000_000
                            style = get_edge_style(speed_bps)

                            edges.append({
                                "from": nb["switch_id"],
                                "to": target_id,
                                "label": f"{style['speed_label']}\n{proto} ({l_port} ↔ {r_port})",
                                "title": f"連結速率: {style['speed_label']}<br>通訊協定: {proto}<br>本端埠: {l_port}<br>對端埠: {r_port}",
                                "color": style["color"],
                                "width": style["width"],
                                "smooth": {"type": "continuous"}
                            })

            # Add Core Nodes (Firewall & Gateway)
            if fw_ip:
                fw_name = net_cfg.get("firewall_name", "核心防火牆")
                nodes.append({
                    "id": fw_id,
                    "label": f"🛡️ {fw_name}\n({fw_ip})\n[出口防護 / Level 0]",
                    "title": f"出口防火牆: {fw_name}<br>IP: {fw_ip}<br>角色: 邊界安全與出口路由",
                    "shape": "box",
                    "margin": 12,
                    "level": 0,
                    "font": {"color": "#FFFFFF", "size": 14, "bold": True},
                    "color": {"background": "#E11D48", "border": "#BE123C", "highlight": "#F43F5E"},
                    "poll_status": "CORE_NODE",
                    "vendor": "Firewall",
                    "management_ip": fw_ip,
                    "fdb_count": 0,
                    "alert_count": 0,
                    "is_root": False,
                })

            if gw_ip:
                gw_name = net_cfg.get("gateway_name", "校園核心閘道 (Root)")
                nodes.append({
                    "id": gw_id,
                    "label": f"🌐 {gw_name}\n({gw_ip})\n[★ 核心 Root / Level 1 ★]",
                    "title": f"核心閘道 (Root): {gw_name}<br>IP: {gw_ip}<br>角色: 內部路由中心、預設閘道與 VLAN 匯聚",
                    "shape": "box",
                    "margin": 14,
                    "level": 1,
                    "font": {"color": "#FFFFFF", "size": 15, "bold": True},
                    "color": {"background": "#6D28D9", "border": "#4C1D95", "highlight": "#8B5CF6"},
                    "poll_status": "CORE_NODE",
                    "vendor": "Gateway",
                    "management_ip": gw_ip,
                    "fdb_count": 0,
                    "alert_count": 0,
                    "is_root": True,
                })

            # Connect Firewall -> Gateway (10G 綠線)
            if fw_ip and gw_ip:
                fw_style = get_edge_style(10_000_000_000, "WAN 出口骨幹")
                edges.append({
                    "from": fw_id,
                    "to": gw_id,
                    "label": f"{fw_style['speed_label']}\nWAN / 預設路由",
                    "title": "防火牆至核心閘道之 10G 骨幹連接",
                    "color": fw_style["color"],
                    "width": fw_style["width"],
                    "smooth": {"type": "continuous"}
                })

            # Connect Gateway (Root) -> Core Switches or Subnet switches
            if gw_ip:
                # 10G links to designated core switches, 1G links to other distribution switches
                connected_sw = False
                for core_id in core_switch_ids:
                    c_style = get_edge_style(10_000_000_000, "Core Trunk")
                    edges.append({
                        "from": gw_id,
                        "to": core_id,
                        "label": f"{c_style['speed_label']}\nTrunk 核心骨幹",
                        "title": f"核心閘道 (Root) 至核心交換器 ({core_id}) 10G 鏈結",
                        "color": c_style["color"],
                        "width": c_style["width"],
                        "smooth": {"type": "continuous"}
                    })
                    connected_sw = True

                # If no core switches identified, connect Gateway to switches in subnet
                if not connected_sw:
                    gw_prefix = ".".join(gw_ip.split(".")[:3]) + "." if "." in gw_ip else ""
                    for sw in sw_rows:
                        sw_ip = sw["management_ip"] or ""
                        if gw_prefix and sw_ip.startswith(gw_prefix) and sw["poll_status"] == "ONLINE_SNMP_OK":
                            g_style = get_edge_style(1_000_000_000, "LAN Trunk")
                            edges.append({
                                "from": gw_id,
                                "to": sw["switch_id"],
                                "label": f"{g_style['speed_label']}\nLAN Trunk",
                                "title": f"核心閘道 (Root) 鏈接至 {sw['sys_name'] or sw_ip}",
                                "color": g_style["color"],
                                "width": g_style["width"],
                                "dashes": True,
                                "smooth": {"type": "continuous"}
                            })
                            connected_sw = True
                            break

            return {
                "status": "success",
                "data": {
                    "nodes": nodes,
                    "edges": edges,
                    "root_id": gw_id,
                    "core_nodes": {"gateway_ip": gw_ip, "firewall_ip": fw_ip, "core_switch_ip": core_sw_ip}
                }
            }
        finally:
            connection.close()

    @app.get(f"{route_prefix}/topology/core-nodes")
    def get_core_nodes():
        """Retrieve configured core nodes (Gateway & Firewall)."""
        cfg = load_config()
        net_cfg = cfg.get("network", {})
        return {
            "status": "success",
            "data": {
                "gateway_ip": net_cfg.get("gateway_ip", ""),
                "gateway_name": net_cfg.get("gateway_name", "校園核心閘道 (Gateway)"),
                "firewall_ip": net_cfg.get("firewall_ip", ""),
                "firewall_name": net_cfg.get("firewall_name", "核心防火牆 (FortiGate)"),
                "core_switch_ip": net_cfg.get("core_switch_ip", ""),
            }
        }

    @app.post(f"{route_prefix}/topology/core-nodes")
    def update_core_nodes(req: CoreNodesRequest):
        """Update core nodes in config.yaml."""
        import yaml
        cfg_path = project_path("config.yaml")
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

        if "network" not in cfg:
            cfg["network"] = {}

        if req.gateway_ip is not None:
            cfg["network"]["gateway_ip"] = req.gateway_ip.strip()
        if req.gateway_name is not None:
            cfg["network"]["gateway_name"] = req.gateway_name.strip()
        if req.firewall_ip is not None:
            cfg["network"]["firewall_ip"] = req.firewall_ip.strip()
        if req.firewall_name is not None:
            cfg["network"]["firewall_name"] = req.firewall_name.strip()
        if req.core_switch_ip is not None:
            cfg["network"]["core_switch_ip"] = req.core_switch_ip.strip()

        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)

        return {"status": "success", "message": "核心網路節點設定已更新", "data": cfg["network"]}

    @app.get(f"{route_prefix}/diagnostics/summary")
    def get_diagnostics_summary():
        """Return mutually exclusive 5-category switch counts matching switches.yaml total exactly."""
        import yaml
        sw_path = project_path("config/switches.yaml")
        all_yaml_switches = []
        if os.path.exists(sw_path):
            try:
                with open(sw_path, "r", encoding="utf-8") as f:
                    ydata = yaml.safe_load(f) or {}
                    all_yaml_switches = ydata.get("switches", [])
            except Exception:
                pass

        total_switches = len(all_yaml_switches)
        connection = connect_readonly_database(database_path)
        try:
            # Query current switch poll statuses & neighbor counts
            sw_dict = {}
            cur = connection.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='switches'")
            if cur.fetchone():
                rows = connection.execute(
                    """SELECT s.management_ip, s.poll_status,
                              (SELECT COUNT(*) FROM switch_neighbors n WHERE n.switch_id = s.switch_id) as neighbor_count
                       FROM switches s"""
                ).fetchall()
                for r in rows:
                    sw_dict[r["management_ip"]] = {
                        "poll_status": r["poll_status"],
                        "neighbor_count": r["neighbor_count"] or 0
                    }

            # Mutually exclusive categorization (MECE):
            normal_cnt = 0
            isolated_cnt = 0
            snmp_degraded_cnt = 0
            offline_cnt = 0
            disabled_cnt = 0

            for ysw in all_yaml_switches:
                if not ysw:
                    continue
                ip = ysw.get("management_ip")
                is_enabled = bool(ysw.get("enabled", True))
                db_info = sw_dict.get(ip, {})
                status = db_info.get("poll_status", "ONLINE_SNMP_OK" if is_enabled else "SNMP_UNCONFIGURED")
                nb_cnt = db_info.get("neighbor_count", 0)

                # 1. 待設定 (enabled: false)
                if not is_enabled or status == "SNMP_UNCONFIGURED":
                    disabled_cnt += 1
                # 2. 實體離線
                elif status == "HOST_OFFLINE":
                    offline_cnt += 1
                # 3. Ping 在線但 SNMP 障礙
                elif status in ("COMMUNITY_MISCONFIGURED", "SNMP_DEGRADED"):
                    snmp_degraded_cnt += 1
                # 4. 在線但孤立無 LLDP 鄰居
                elif nb_cnt == 0:
                    isolated_cnt += 1
                # 5. 完全正常 (有 SNMP 且有鄰居連線)
                else:
                    normal_cnt += 1

            return {
                "status": "success",
                "data": {
                    "switch_counts": {
                        "total": total_switches,
                        "normal": normal_cnt,
                        "isolated": isolated_cnt,
                        "snmp_degraded": snmp_degraded_cnt,
                        "offline": offline_cnt,
                        "disabled": disabled_cnt,
                    }
                }
            }
        finally:
            connection.close()

    @app.get(f"{route_prefix}/topology/locate")
    def locate_device(q: str = Query(min_length=1, max_length=100)):
        """Locate physical switch and port for a given IP or MAC address."""
        connection = connect_readonly_database(database_path)
        try:
            target = q.strip().upper()
            row = connection.execute(
                """SELECT f.mac_address, f.switch_id, f.bridge_port, f.if_index, f.vlan_id, f.last_updated,
                          s.sys_name as switch_name, s.management_ip as switch_ip, s.vendor, s.model,
                          d.hostname, d.last_ip, d.device_name
                   FROM switch_fdb_current f
                   JOIN switches s ON f.switch_id = s.switch_id
                   LEFT JOIN devices d ON f.mac_address = UPPER(d.mac)
                   WHERE f.mac_address = ? OR d.last_ip = ?
                   ORDER BY f.last_updated DESC LIMIT 1""",
                (target, target)
            ).fetchone()

            if not row:
                # Try finding from dhcp_events
                ev = connection.execute(
                    """SELECT client_mac, assigned_ip, requested_ip, hostname, vlan_id, event_time
                       FROM dhcp_events
                       WHERE client_mac = ? OR assigned_ip = ? OR requested_ip = ?
                       ORDER BY event_time DESC LIMIT 1""",
                    (target, target, target)
                ).fetchone()
                if ev:
                    # check if fdb has client_mac
                    fdb_match = connection.execute(
                        """SELECT f.*, s.sys_name as switch_name, s.management_ip as switch_ip
                           FROM switch_fdb_current f
                           JOIN switches s ON f.switch_id = s.switch_id
                           WHERE f.mac_address = ? ORDER BY f.last_updated DESC LIMIT 1""",
                        (ev["client_mac"].upper(),)
                    ).fetchone()
                    if fdb_match:
                        return {"status": "success", "found": True, "data": dict(fdb_match)}

                return {"status": "success", "found": False, "message": f"未在交換器 FDB 中找到目標: {q}"}

            return {"status": "success", "found": True, "data": dict(row)}
        finally:
            connection.close()

    return app


app = create_query_app()

