"""Click CLI commands for netmon tool."""

from __future__ import annotations
import sys
import os
import subprocess
import time
import yaml
import click
from datetime import datetime
from typing import Any

from ..config import load_settings
from ..storage.database import Database
from ..storage.repository import NetworkRepository
from ..topology.resolver import TopologyResolver
from ..dhcp.listener import DHCPListener
from ..dhcp.parser import DHCPParser


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to standard format."""
    if not mac:
        return ""
    clean = "".join(c for c in mac if c.isalnum()).upper()
    if len(clean) == 12:
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))
    return mac.upper()


def format_ts(val: Any) -> str:
    """Format datetime or timestamp string to YYYY-MM-DD_HH:MM:SS."""
    if not val:
        return ""
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d_%H:%M:%S")
    s = str(val)
    if " " in s:
        return s.replace(" ", "_", 1)
    return s


def auto_detect_active_interface() -> str:
    """自動掃描 Scapy 介面，尋找帶有有效實體 IP 的網卡介面"""
    try:
        from scapy.all import get_if_list, get_if_addr
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0" and not ip.startswith("127."):
                    return iface
            except Exception:
                continue
    except Exception:
        pass
    return ""


@click.group()
@click.option("--config", default="config/settings.yaml", help="Path to settings.yaml")
@click.option("--switches", default="config/switches.yaml", help="Path to switches.yaml")
@click.pass_context
def cli(ctx: click.Context, config: str, switches: str) -> None:
    """School Network Monitor CLI tool."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["switches_path"] = switches


@cli.command("check-snmp")
@click.option("--switch", "-s", default="", help="指定要測試的交換器 IP 或名稱（若不指定則測試所有交換器）")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed SNMP response info")
@click.pass_context
def check_snmp_cmd(ctx: click.Context, switch: str, verbose: bool) -> None:
    """Test SNMP connectivity for specific or all configured switches (bypass enabled status)."""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    db.init_schema()
    repo = NetworkRepository(db)
    from ..snmp.collector import SNMPCollector
    collector = SNMPCollector(repo)

    all_switches = settings.switches
    if not all_switches:
        click.secho("⚠️ 找不到任何交換器設定（switches.yaml 為空）。", fg="yellow")
        return

    targets = all_switches
    if switch:
        targets = [sw for sw in all_switches if sw.management_ip == switch or sw.name == switch]
        if not targets:
            click.secho(f"⚠️ 找不到符合條件的交換器: {switch}", fg="red")
            return

    click.echo(f"🔍 開始測試 SNMP 連線（共檢測 {len(targets)} 台交換器）...\n")

    success_count = 0
    for idx, sw in enumerate(targets, 1):
        display_name = f"{sw.name} ({sw.management_ip})"
        status_tag = "啟用" if sw.enabled else "停用/略過"
        click.echo(f"[{idx}/{len(targets)}] 正在測試: {display_name} [狀態: {status_tag}]...", nl=False)
        
        try:
            success = collector.poll_switch(sw, settings.snmp)
            if success:
                click.secho(" [成功]", fg="green", bold=True)
                success_count += 1
            else:
                click.secho(" [失敗 / 逾時]", fg="red")
        except Exception as e:
            click.secho(f" [失敗: {e}]", fg="red")
            if verbose:
                import traceback
                traceback.print_exc()

    click.echo(f"\n✨ SNMP 測試結束。成功: {success_count} / 總數: {len(targets)}")


@cli.command("poll-switches")
@click.pass_context
def poll_switches_cmd(ctx: click.Context) -> None:
    """Poll switches for interface and FDB data."""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    db.init_schema()

    try:
        from ..storage.migrations import apply_migrations
        apply_migrations(db)
    except Exception:
        pass

    repo = NetworkRepository(db)

    enabled_switches = [sw for sw in settings.switches if sw.enabled]
    total = len(enabled_switches)
    click.echo(f"🚀 開始輪詢 {total} 台啟用的交換器 (FDB 與連接埠介面)...")

    try:
        from ..snmp.collector import SNMPCollector
        collector = SNMPCollector(repo)

        for idx, sw in enumerate(enabled_switches, 1):
            display_name = f"{sw.name} ({sw.management_ip})"
            click.echo(f"[{idx}/{total}] 正在採集: {display_name}...", nl=False)
            try:
                success = collector.poll_switch(sw, settings.snmp)
                if success:
                    click.echo(" [成功]")
                else:
                    click.echo(" [失敗]")
            except Exception as e:
                click.echo(f" [失敗: {e}]")

        click.echo("✅ Polling completed successfully.")
    except Exception as e:
        click.secho(f"⚠️ Polling execution error: {e}", fg="red")
        raise e


@cli.command("poll-fdb")
@click.pass_context
def poll_fdb_cmd(ctx: click.Context) -> None:
    """Poll FDB and interface tables from all enabled switches."""
    ctx.invoke(poll_switches_cmd)


@cli.command("show-interfaces")
@click.option("--switch", required=True, help="Switch IP address or name")
@click.pass_context
def show_interfaces_cmd(ctx: click.Context, switch: str) -> None:
    """Show interface mappings for a specific switch."""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    switches = repo.list_switches()
    target_sw = next((s for s in switches if s.management_ip == switch or s.sys_name == switch or str(s.switch_id) == switch), None)
    if not target_sw or not target_sw.switch_id:
        click.secho(f"Switch not found: {switch}", fg="red")
        return

    intfs = repo.get_interfaces(target_sw.switch_id)
    click.echo("==================================================")
    click.echo(f" Interfaces for Switch: {target_sw.sys_name} ({target_sw.management_ip})")
    click.echo("==================================================")
    click.echo(f"{'ifIndex':<8} {'BridgePort':<12} {'Interface Name':<20} {'Alias':<25} {'Uplink'}")
    click.echo("-" * 75)
    for idx, i_obj in sorted(intfs.items()):
        bp = str(i_obj.bridge_port) if i_obj.bridge_port is not None else "N/A"
        up_str = "Yes" if i_obj.is_uplink else "No"
        click.echo(f"{idx:<8} {bp:<12} {i_obj.if_name:<20} {i_obj.if_alias:<25} {up_str}")
    click.echo("==================================================")


@cli.command("verify-mac")
@click.argument("mac")
@click.option("--switch-ip", required=True, help="Verified switch management IP")
@click.option("--port", required=True, help="Verified interface name or index")
@click.option("--note", default="", help="Verification notes")
@click.pass_context
def verify_mac_cmd(ctx: click.Context, mac: str, switch_ip: str, port: str, note: str) -> None:
    """Record physical administrator verification for a target MAC address."""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    success, msg, is_match = repo.verify_and_evaluate_location(mac, switch_ip, port, note)
    if success:
        if is_match:
            click.secho(f"✅ {msg}", fg="green", bold=True)
        else:
            click.secho(f"⚠️ {msg}", fg="magenta", bold=True)
    else:
        click.secho(f"❌ 驗證失敗: {msg}", fg="red")


@cli.command("find-mac")
@click.argument("mac")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed diagnostic breakdown for MAC resolution")
@click.pass_context
def find_mac_cmd(ctx: click.Context, mac: str, verbose: bool) -> None:
    """Find physical switch port location for a given MAC address with diagnostic options."""
    clean_mac = normalize_mac(mac)
    if not clean_mac:
        click.secho(f"Invalid MAC format: {mac}", fg="red")
        sys.exit(1)

    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)
    resolver = TopologyResolver(repo)

    fdb_entries = repo.get_fdb_for_mac(clean_mac)
    switches_map = {s.switch_id: s for s in repo.list_switches() if s.switch_id is not None}
    verification = repo.get_latest_verification(clean_mac)

    click.echo("==================================================")
    click.echo(f" MAC Location Diagnostic Report: {clean_mac}")
    click.echo("==================================================")

    if verification:
        click.echo(" [Physical Verification]")
        click.echo(f"   Status:         {'VERIFIED (Match)' if verification.is_match else 'CONFLICT (Mismatch)'}")
        click.echo(f"   Verified At:    {format_ts(verification.verified_at)}")
        click.echo(f"   Note:           {verification.note or 'None'}")
    else:
        click.echo(" [Physical Verification]: Pending (Inferred by algorithm)")

    if verbose:
        click.echo(f"\n [Raw FDB Candidates ({len(fdb_entries)} found)]")
        for entry in fdb_entries:
            sw = switches_map.get(entry.switch_id)
            sw_name = sw.sys_name if sw else f"SW-{entry.switch_id}"
            sw_ip = sw.management_ip if sw else "unknown"
            status = sw.poll_status if sw else "online"

            intfs = repo.get_interfaces(entry.switch_id) if entry.switch_id else {}
            intf = intfs.get(entry.if_index) if entry.if_index else None

            intf_name = intf.if_name if intf else f"Index-{entry.if_index}"
            is_up = intf.is_uplink if intf else False

            click.echo(f"   - Switch: {sw_name} ({sw_ip}) [Poll Status: {status}]")
            click.echo(f"     -> Bridge Port: {entry.bridge_port} | ifIndex: {entry.if_index}")
            click.echo(f"     -> Interface:   {intf_name} (Alias: {intf.if_alias if intf else ''})")
            click.echo(f"     -> Is Uplink:   {'Yes (Filtered)' if is_up else 'No (Edge Access)'}")
            click.echo(f"     -> FDB Seen At: {format_ts(entry.last_seen)}")

    loc = resolver.resolve_mac(clean_mac)
    click.echo("\n [Resolution Result]")
    click.echo(f"   Status:         {loc.resolution_status.value.upper()}")
    click.echo(f"   Confidence:     {loc.confidence * 100:.0f}%")
    click.echo(f"   Reason:         {loc.reason}")

    if loc.switch_id:
        sw = switches_map.get(loc.switch_id)
        intfs = repo.get_interfaces(loc.switch_id) if loc.switch_id else {}
        i_obj = intfs.get(loc.if_index) if loc.if_index else None
        click.echo(f"   Selected Switch: {sw.sys_name if sw else loc.switch_id} ({sw.management_ip if sw else ''})")
        click.echo(f"   Selected Port:   {i_obj.if_name if i_obj else loc.if_index}")
    click.echo("==================================================")


@cli.command("listen-dhcp")
@click.option("--interface", "-i", default="", help="Capture network interface name or Npcap GUID")
@click.option("--auto-config", is_flag=True, help="自動偵測目前帶有有效 IP 的實體網卡並寫入 settings.yaml")
@click.pass_context
def listen_dhcp_cmd(ctx: click.Context, interface: str, auto_config: bool) -> None:
    """Passively listen to DHCP traffic and record leases/events with Rogue & Scope validation."""
    config_file = ctx.obj["config_path"]
    
    selected_iface = interface
    if auto_config or not selected_iface:
        detected = auto_detect_active_interface()
        if detected:
            click.secho(f"🔍 自動偵測到有效實體網卡介面: {detected}", fg="cyan")
            selected_iface = detected
            if auto_config:
                try:
                    with open(config_file, "r", encoding="utf-8") as f:
                        doc = yaml.safe_load(f) or {}
                    if "capture" not in doc:
                        doc["capture"] = {}
                    doc["capture"]["interface"] = detected
                    doc["capture"]["enabled"] = True
                    with open(config_file, "w", encoding="utf-8") as f:
                        yaml.safe_dump(doc, f, allow_unicode=True)
                    click.secho(f"✅ 已成功將網卡介面寫入設定檔: {config_file}", fg="green", bold=True)
                except Exception as e:
                    click.secho(f"⚠️ 自動寫入 settings.yaml 失敗: {e}", fg="red")

    # 載入設定與初始化資料庫儲存庫
    settings = load_settings(config_file, ctx.obj["switches_path"])
    db = Database(settings.database.path)
    db.init_schema()
    repo = NetworkRepository(db)

    # 嚴格從 settings.yaml 載入 authorized_servers 與 scope_rules，不寫死於程式碼中
    authorized_servers = list(getattr(settings.dhcp, "authorized_servers", []))
    raw_scope_rules = getattr(settings.dhcp, "scope_rules", [])

    formatted_rules = []
    for r in raw_scope_rules:
        # 相容 dict 或 pydantic 物件屬性讀取
        m_list = r.get("macs", []) if isinstance(r, dict) else getattr(r, "macs", [])
        s_list = r.get("allowed_servers", []) if isinstance(r, dict) else getattr(r, "allowed_servers", [])
        g_name = r.get("group_name", "Target Group") if isinstance(r, dict) else getattr(r, "group_name", "Target Group")
        
        f_macs = {normalize_mac(m) for m in m_list if m}
        allowed = set(s_list)
        formatted_rules.append({"group_name": g_name, "macs": f_macs, "allowed_servers": allowed})

    display_iface = selected_iface if selected_iface else "Default Network Interface"

    click.echo(f"🚀 Starting passive DHCP listener on interface: [{display_iface}]")
    click.echo(f"🛡️  Authorized DHCP Servers: {authorized_servers}")
    click.echo(f"📋 Loaded {len(formatted_rules)} scope restriction rule(s) from config.")
    click.echo("Press Ctrl+C to stop safely.\n")

    stats = {"packets": 0, "parsed": 0, "errors": 0, "saved": 0, "rogue": 0, "mismatch": 0}

    def packet_callback(event):
        stats["packets"] += 1
        try:
            if event:
                stats["parsed"] += 1
                t_str = event.timestamp.strftime("%Y-%m-%d_%H:%M:%S") if event.timestamp else datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
                m_type = event.message_type
                msg_type_str = m_type.value if hasattr(m_type, "value") else str(m_type)
                server_ip = getattr(event, "dhcp_server_id", None) or "0.0.0.0"
                client_mac = normalize_mac(event.mac or "")
                ip_addr = event.ip or event.requested_ip or ""

                is_rogue = False
                is_mismatch = False
                alert_status = "NORMAL"

                if msg_type_str in ["OFFER", "ACK", "NAK"]:
                    if server_ip and server_ip != "0.0.0.0" and (server_ip not in authorized_servers):
                        is_rogue = True
                        alert_status = f"[ROGUE DHCP: {server_ip}]"
                        stats["rogue"] += 1
                        if hasattr(repo, "record_alert"):
                            repo.record_alert("ROGUE_DHCP", server_ip, client_mac, ip_addr, f"Unauthorized server offered IP {ip_addr}")

                    for rule in formatted_rules:
                        if client_mac in rule["macs"] and server_ip not in rule["allowed_servers"]:
                            is_mismatch = True
                            alert_status = f"[SCOPE MISMATCH: {server_ip}]"
                            stats["mismatch"] += 1
                            if hasattr(repo, "record_alert"):
                                repo.record_alert("SCOPE_MISMATCH", server_ip, client_mac, ip_addr, f"Group {rule['group_name']} violated by server {server_ip}")
                            break

                repo.record_dhcp_event(event)
                stats["saved"] += 1

                output_line = (
                    f"[{t_str}] {alert_status:<30} "
                    f"| Type: {msg_type_str:<8} "
                    f"| Server: {server_ip:<15} "
                    f"| Client MAC: {client_mac} "
                    f"| IP: {ip_addr}"
                )

                if is_rogue:
                    click.secho(output_line, fg="red", bold=True)
                elif is_mismatch:
                    click.secho(output_line, fg="magenta", bold=True)
                elif msg_type_str == "ACK":
                    click.secho(output_line, fg="green")
                elif msg_type_str == "NAK":
                    click.secho(output_line, fg="yellow")
                else:
                    click.echo(output_line)

        except Exception as e:
            stats["errors"] += 1
            import traceback
            click.secho(f"⚠️ 解析封包發生例外: {e}", fg="red")
            traceback.print_exc()

    listener = DHCPListener(interface=selected_iface, callback=packet_callback)
    listener.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        click.echo("\n🛑 Stopping DHCP listener gracefully...")
        listener.stop()
        click.echo(
            f"📊 Session Summary: Total Packets: {stats['packets']} | "
            f"Parsed: {stats['parsed']} | Saved: {stats['saved']} | "
            f"Rogue Alerts: {stats['rogue']} | Scope Mismatches: {stats['mismatch']} | "
            f"Errors: {stats['errors']}"
        )


@cli.command("find-ip")
@click.argument("ip")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed diagnostic breakdown for IP and MAC correlation")
@click.pass_context
def find_ip_cmd(ctx: click.Context, ip: str, verbose: bool) -> None:
    """Find physical switch port and lease details for a given IP address."""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)
    resolver = TopologyResolver(repo)

    dev = repo.get_device_by_ip(ip)
    if not dev:
        click.secho(f"No device record found for IP: {ip}", fg="yellow")
        return

    clean_mac = dev.mac
    verification = repo.get_latest_verification(clean_mac)
    loc = resolver.resolve_mac(clean_mac)
    switches_map = {s.switch_id: s for s in repo.list_switches() if s.switch_id is not None}

    click.echo("==================================================")
    click.echo(f" IP Location & Lease Diagnostic Report: {ip}")
    click.echo("==================================================")
    click.echo(" [IP & MAC Mapping]")
    click.echo(f"   IP Address:     {dev.current_ip}")
    click.echo(f"   MAC Address:    {clean_mac}")
    click.echo(f"   Hostname:       {dev.hostname or 'Unknown'}")

    click.echo("\n [DHCP Lease Status]")
    click.echo(f"   Lease Status:   {getattr(dev, 'lease_status', 'observed').upper()}")
    click.echo(f"   Last Seen:      {format_ts(dev.last_seen)}")

    click.echo("\n [Resolution Result]")
    click.echo(f"   Status:         {loc.resolution_status.value.upper()}")
    click.echo(f"   Confidence:     {loc.confidence * 100:.0f}%")
    click.echo(f"   Reason:         {loc.reason}")

    if loc.switch_id:
        sw = switches_map.get(loc.switch_id)
        intfs = repo.get_interfaces(loc.switch_id)
        i_obj = intfs.get(loc.if_index) if loc.if_index else None
        click.echo(f"   Selected Switch: {sw.sys_name if sw else loc.switch_id} ({sw.management_ip if sw else ''})")
        click.echo(f"   Selected Port:   {i_obj.if_name if i_obj else loc.if_index}")

    if verification:
        click.echo("\n [Physical Verification]")
        click.echo(f"   Status:         {'VERIFIED (Match)' if verification.is_match else 'CONFLICT (Mismatch)'}")
        click.echo(f"   Note:           {verification.note or 'None'}")

    click.echo("==================================================")


@cli.command("export-csv")
@click.option("--output", default="network_device_report.csv", help="Output CSV file path for devices")
@click.option("--alert-output", default="dhcp_security_alerts.csv", help="Output CSV file path for security alerts")
@click.pass_context
def export_csv_cmd(ctx: click.Context, output: str, alert_output: str) -> None:
    """Export comprehensive device inventory and DHCP security alerts to CSV files."""
    import csv
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    rows = repo.get_comprehensive_export_rows()
    try:
        with open(output, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "MAC Address", "Current IP", "Hostname", "Device Name", "Device Type",
                "IP Assignment", "Lease Status", "Lease Expiry", "Last Seen",
                "Switch Name", "Switch IP", "Interface Name", "Confidence",
                "Resolution Status", "Verification Match", "Last Verified At", "Reason"
            ])
            for r in rows:
                writer.writerow([
                    r.get("mac"),
                    r.get("current_ip"),
                    r.get("hostname"),
                    r.get("device_name"),
                    r.get("device_type"),
                    r.get("ip_assignment_type"),
                    r.get("lease_status"),
                    format_ts(r.get("lease_expiry")),
                    format_ts(r.get("last_seen")),
                    r.get("switch_name"),
                    r.get("switch_ip"),
                    r.get("interface_name"),
                    f"{r.get('confidence', 0)*100:.0f}%" if r.get("confidence") is not None else "0%",
                    r.get("resolution_status", "unknown"),
                    "VERIFIED (Match)" if r.get("last_verification_match") == 1 else ("CONFLICT" if r.get("last_verification_match") == 0 else "Unverified"),
                    format_ts(r.get("last_verified_at")),
                    r.get("reason", "N/A")
                ])
        click.secho(f"✅ Successfully exported comprehensive device report to: {output}", fg="green")
    except Exception as e:
        click.secho(f"⚠️ Failed to export device CSV: {e}", fg="red")

    try:
        alerts = repo.list_all_alerts() if hasattr(repo, "list_all_alerts") else []
        with open(alert_output, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Timestamp", "Alert Type", "Server IP", "Client MAC", "Assigned IP", "Details"])
            for a in alerts:
                writer.writerow([
                    a.get("id"), format_ts(a.get("timestamp")), a.get("alert_type"),
                    a.get("server_ip"), a.get("client_mac"), a.get("assigned_ip"), a.get("details")
                ])
        click.secho(f"✅ Successfully exported security alerts report to: {alert_output}", fg="green")
    except Exception as e:
        click.secho(f"⚠️ Failed to export security alerts CSV: {e}", fg="red")


@cli.command("list-devices")
@click.option("--type", "device_type", default=None, help="篩選設備類型 (desktop, server, printer, ...)")
@click.option("--status", "mgmt_status", default=None, help="篩選管理狀態 (UNMANAGED, MANAGED, RETIRED)")
@click.option("--assignment", "assign_type", default=None, help="篩選 IP 配置 (DHCP, STATIC, ...)")
@click.option("--location", "loc_status", default=None, help="篩選定位狀態 (confirmed, candidate, unresolved, verified)")
@click.pass_context
def list_devices_cmd(ctx: click.Context, device_type: str, mgmt_status: str, assign_type: str, loc_status: str) -> None:
    """列出校園有線網路設備清冊 (支援各項條件篩選)。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    db.init_schema()
    
    from ..storage.migrations import apply_migrations
    apply_migrations(db)

    repo = NetworkRepository(db)
    devices = repo.list_inventory_devices(
        device_type=device_type,
        management_status=mgmt_status,
        assignment_type=assign_type,
        location_status=loc_status,
    )

    click.echo("========================================================================================================")
    click.echo(f" 校園網路設備清冊 (共 {len(devices)} 台設備)")
    click.echo("========================================================================================================")
    header = f"{'ID':<4} {'MAC Address':<18} {'Current IP':<16} {'Device Name':<16} {'Type':<10} {'Assign':<8} {'Switch Port':<20} {'Location Status'}"
    click.echo(header)
    click.echo("-" * 104)

    for d in devices:
        sw_port = "N/A"
        if d.get("switch_name") and d.get("interface_name"):
            sw_port = f"{d['switch_name']}:{d['interface_name']}"
        elif d.get("switch_id"):
            sw_port = f"SW-{d['switch_id']}:{d.get('if_index', 'N/A')}"

        loc_status_str = (d.get("resolution_status") or "UNKNOWN").upper()
        name_str = d.get("device_name") or d.get("hostname") or "Unknown"

        click.echo(
            f"{d['device_id']:<4} "
            f"{d['mac_address']:<18} "
            f"{(d.get('current_ip') or 'None'):<16} "
            f"{name_str[:15]:<16} "
            f"{(d.get('device_type') or 'UNKNOWN'):<10} "
            f"{(d.get('ip_assignment_type') or 'UNKNOWN'):<8} "
            f"{sw_port[:19]:<20} "
            f"{loc_status_str}"
        )
    click.echo("========================================================================================================")


@cli.command("find-device")
@click.argument("identifier")
@click.option("--verbose", "-v", is_flag=True, help="顯示詳細網路定位證據與歷程 IP")
@click.pass_context
def find_device_cmd(ctx: click.Context, identifier: str, verbose: bool) -> None:
    """依設備 ID、MAC 或 IP 查詢統一設備清冊與定位可信度資訊。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    dev = repo.find_inventory_device(identifier)
    if not dev:
        click.secho(f"⚠️ 找不到相符的設備紀錄: {identifier}", fg="yellow")
        return

    clean_mac = dev["mac_address"]
    click.echo("==================================================")
    click.echo(f" 設備綜合診斷報告: {clean_mac}")
    click.echo("==================================================")
    click.echo(" [Device Identity]")
    click.echo(f"   Device ID:      {dev['device_id']}")
    click.echo(f"   Device Name:    {dev.get('device_name') or '未設定'}")
    click.echo(f"   MAC Address:    {dev['mac_address']}")
    click.echo(f"   Device Type:    {dev.get('device_type')}")
    click.echo(f"   Management:     {dev.get('management_status')}")
    click.echo(f"   Record Source:  {dev.get('record_source')}")

    click.echo("\n [IP Assignment]")
    click.echo(f"   Current IP:     {dev.get('current_ip') or 'None'}")
    click.echo(f"   Assignment:     {dev.get('ip_assignment_type')}")
    click.echo(f"   Hostname:       {dev.get('hostname') or 'Unknown'}")
    click.echo(f"   Lease Status:   {(dev.get('lease_status') or 'UNKNOWN').upper()}")
    click.echo(f"   Lease Expiry:   {format_ts(dev.get('lease_expiry')) or 'N/A'}")

    click.echo("\n [Network Location]")
    sw_display = dev.get("switch_name") or (f"Switch-ID-{dev['switch_id']}" if dev.get("switch_id") else "Unknown")
    click.echo(f"   Switch:         {sw_display} ({dev.get('switch_ip') or 'N/A'})")
    click.echo(f"   Interface:      {dev.get('interface_name') or dev.get('if_index') or 'Unknown'}")
    click.echo(f"   Location Status:{(dev.get('resolution_status') or 'UNKNOWN').upper()}")
    conf = dev.get("confidence")
    click.echo(f"   Confidence:     {conf * 100:.0f}%" if conf is not None else "   Confidence:     0%")
    click.echo(f"   Reason:         {dev.get('reason') or 'N/A'}")

    verification = repo.get_latest_verification(clean_mac)
    click.echo("\n [Evidence & Verification]")
    if verification:
        click.echo(f"   Verification:   {'VERIFIED (Match)' if verification.is_match else 'CONFLICT (Mismatch)'}")
        click.echo(f"   Verified At:    {format_ts(verification.verified_at)}")
        click.echo(f"   Notes:          {verification.note or 'None'}")
    else:
        click.echo("   Verification:   Pending (Inferred by algorithm / Unverified)")

    click.echo(f"   First Seen:     {format_ts(dev.get('first_seen'))}")
    click.echo(f"   Last Observed:  {format_ts(dev.get('last_seen'))}")

    if verbose:
        ip_history = repo.get_ip_history_for_device(dev["device_id"])
        click.echo(f"\n [IP Assignment History ({len(ip_history)} entries)]")
        for h in ip_history:
            curr_str = "[CURRENT]" if h["is_current"] else "[HISTORICAL]"
            click.echo(f"   - {h['ip_address']:<16} ({h['assignment_type']}) {curr_str} From: {format_ts(h['valid_from'])} To: {format_ts(h['valid_until']) or 'Now'}")
    click.echo("==================================================")


@cli.command("add-device")
@click.option("--mac", required=True, help="設備 MAC 位址 (例如 00:11:22:33:44:55)")
@click.option("--ip", default="", help="指定 IP 位址 (若為靜態)")
@click.option("--name", default="", help="設備名稱 (例如 資訊組伺服器)")
@click.option("--type", "device_type", default="unknown", help="設備類型 (desktop, laptop, printer, server, network)")
@click.option("--assignment", "assignment_type", default="STATIC", help="IP 配置類型 (STATIC, DHCP, RESERVATION)")
@click.option("--vlan", type=int, default=None, help="VLAN 編號")
@click.option("--notes", default="", help="管理備註")
@click.pass_context
def add_device_cmd(ctx: click.Context, mac: str, ip: str, name: str, device_type: str, assignment_type: str, vlan: int, notes: str) -> None:
    """手動新增靜態 IP 或保留設備至清冊。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    db.init_schema()
    repo = NetworkRepository(db)

    success, msg = repo.add_static_device(
        mac=mac,
        ip=ip or None,
        device_name=name or None,
        device_type=device_type,
        assignment_type=assignment_type,
        management_status="MANAGED",
        vlan_id=vlan,
        notes=notes or None,
    )
    if success:
        click.secho(f"✅ {msg}", fg="green")
    else:
        click.secho(f"❌ 錯誤: {msg}", fg="red")


@cli.command("update-device")
@click.argument("identifier")
@click.option("--name", default=None, help="更新設備名稱")
@click.option("--ip", default=None, help="更新 IP 位址")
@click.option("--type", "device_type", default=None, help="更新設備類型")
@click.option("--assignment", "assignment_type", default=None, help="更新 IP 配置類型")
@click.option("--status", "mgmt_status", default=None, help="更新管理狀態 (MANAGED, UNMANAGED, RETIRED)")
@click.option("--notes", default=None, help="更新備註")
@click.pass_context
def update_device_cmd(ctx: click.Context, identifier: str, name: str, ip: str, device_type: str, assignment_type: str, mgmt_status: str, notes: str) -> None:
    """依設備 ID、MAC 或 IP 修改設備清冊屬性。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    success, msg = repo.update_device_by_identifier(
        identifier=identifier,
        device_name=name,
        ip=ip,
        device_type=device_type,
        assignment_type=assignment_type,
        management_status=mgmt_status,
        notes=notes,
    )
    if success:
        click.secho(f"✅ {msg}", fg="green")
    else:
        click.secho(f"❌ 錯誤: {msg}", fg="red")


@cli.command("import-devices")
@click.argument("csv_path")
@click.pass_context
def import_devices_cmd(ctx: click.Context, csv_path: str) -> None:
    """透過 CSV 檔案批次匯入或更新設備清冊。"""
    import csv
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    click.echo(f"📂 正在讀取 CSV 檔案: {csv_path} ...")
    success_count = 0
    error_count = 0

    try:
        with open(csv_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row_idx, row in enumerate(reader, 1):
                mac = row.get("MAC") or row.get("mac") or row.get("mac_address")
                ip = row.get("IP") or row.get("ip") or row.get("current_ip")
                name = row.get("設備名稱") or row.get("name") or row.get("device_name")
                dev_type = row.get("類型") or row.get("type") or row.get("device_type") or "unknown"
                assign = row.get("IP配置") or row.get("assignment") or "STATIC"
                notes = row.get("備註") or row.get("notes") or ""

                if not mac or str(mac).strip() == "" or str(mac).lower() == "nan":
                    if not ip:
                        click.secho(f"⚠️ 第 {row_idx} 行略過：缺少 MAC 與 IP 識別資訊。", fg="yellow")
                        error_count += 1
                        continue
                    mac = f"UNKNOWN-{ip}"

                existing = repo.find_inventory_device(mac)
                if existing:
                    ok, msg = repo.update_device_by_identifier(
                        identifier=mac,
                        device_name=name,
                        ip=ip,
                        device_type=dev_type,
                        assignment_type=assign,
                        notes=notes,
                    )
                else:
                    ok, msg = repo.add_static_device(
                        mac=mac,
                        ip=ip,
                        device_name=name,
                        device_type=dev_type,
                        assignment_type=assign,
                        notes=notes,
                    )

                if ok:
                    success_count += 1
                else:
                    click.secho(f"⚠️ 第 {row_idx} 行處理失敗 ({mac}): {msg}", fg="yellow")
                    error_count += 1

        click.echo("\n==================================================")
        click.secho(f"✅ CSV 匯入完成！成功: {success_count} 筆, 失敗/衝突: {error_count} 筆", fg="green", bold=True)
        click.echo("==================================================")
    except Exception as e:
        click.secho(f"❌ 讀取或解析 CSV 發生重大錯誤: {e}", fg="red")


@cli.command("unmanaged-report")
@click.option("--output", default="unmanaged_devices_report.csv", help="匯出未管理設備報表 CSV 路徑")
@click.pass_context
def unmanaged_report_cmd(ctx: click.Context, output: str) -> None:
    """產出並匯出「未管理設備報表」（已聯網但尚未登錄清冊之裝置）。"""
    import csv
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    items = repo.get_unmanaged_devices_report()
    click.echo("=========================================================================================")
    click.echo(f" 未管理設備清單 (發現共 {len(items)} 筆未建檔裝置)")
    click.echo("=========================================================================================")
    click.echo(f"{'MAC Address':<18} {'Last Known IP':<16} {'Hostname':<20} {'Last Seen':<20}")
    click.echo("-" * 75)

    for i in items[:30]:
        click.echo(
            f"{i['mac']:<18} "
            f"{(i.get('current_ip') or 'N/A'):<16} "
            f"{(i.get('hostname') or 'Unknown'):<20} "
            f"{format_ts(i.get('last_seen')):<20}"
        )
    if len(items) > 30:
        click.echo(f"... (其餘 {len(items) - 30} 筆已省略於畫面顯示)")
    click.echo("=========================================================================================")

    try:
        with open(output, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC Address", "Last Known IP", "Hostname", "Last Seen", "Detection Source"])
            for i in items:
                writer.writerow([i["mac"], i.get("current_ip"), i.get("hostname"), format_ts(i.get("last_seen")), i.get("detection_source")])
        click.secho(f"✅ 成功將未管理設備報表匯出至: {output}", fg="green")
    except Exception as e:
        click.secho(f"⚠️ 匯出 CSV 失敗: {e}", fg="red")


@cli.command("conflict-report")
@click.option("--output", default="ip_conflict_report.csv", help="匯出 IP 衝突報表 CSV 路徑")
@click.pass_context
def conflict_report_cmd(ctx: click.Context, output: str) -> None:
    """產出並匯出「IP 衝突與異常報表」（多個 MAC 共用同一 IP 之異常狀況）。"""
    import csv
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    conflicts = repo.get_ip_conflict_report()
    click.echo("=========================================================================================")
    click.echo(f" IP 衝突異常報表 (發現共 {len(conflicts)} 組 IP 衝突)")
    click.echo("=========================================================================================")
    if not conflicts:
        click.secho("✨ 目前網路中沒有發現任何 IP 衝突事件！", fg="green")
        return

    click.echo(f"{'Conflicting IP':<16} {'MAC Count':<10} {'Conflicting MAC Addresses':<40} {'Last Conflict Time'}")
    click.echo("-" * 85)

    for c in conflicts:
        click.echo(
            f"{c['ip']:<16} "
            f"{c['mac_count']:<10} "
            f"{c['conflicting_macs']:<40} "
            f"{format_ts(c.get('last_conflict_time'))}"
        )
    click.echo("=========================================================================================")

    try:
        with open(output, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "MAC Count", "Conflicting MAC Addresses", "Last Conflict Time"])
            for c in conflicts:
                writer.writerow([c["ip"], c["mac_count"], c["conflicting_macs"], format_ts(c.get("last_conflict_time"))])
        click.secho(f"✅ 成功將 IP 衝突報表匯出至: {output}", fg="green")
    except Exception as e:
        click.secho(f"⚠️ 匯出 CSV 失敗: {e}", fg="red")


@cli.command("poll-lldp")
@click.option("--switch", "-s", default="", help="指定交換器 IP (未指定則輪詢全部啟用交換器)")
@click.pass_context
def poll_lldp_cmd(ctx: click.Context, switch: str) -> None:
    """透過 SNMP 輪詢交換器之 LLDP 鄰居資訊。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    from ..snmp.neighbor_collector import NeighborCollector
    collector = NeighborCollector(repo)

    switches = [s for s in settings.switches if s.enabled]
    if switch:
        switches = [s for s in switches if s.management_ip == switch or s.name == switch]

    click.echo(f"🚀 開始採集 {len(switches)} 台交換器的 LLDP 鄰居資訊...")
    total_found = 0
    for sw in switches:
        click.echo(f" -> 正在查詢 {sw.name} ({sw.management_ip})...", nl=False)
        neighbors = collector.poll_lldp_neighbors(sw, settings.snmp)
        if neighbors:
            target_sw = next((s for s in repo.list_switches() if s.management_ip == sw.management_ip), None)
            if target_sw and target_sw.switch_id:
                repo.save_topology_observations(target_sw.switch_id, neighbors)
            click.secho(f" [成功: 找到 {len(neighbors)} 個鄰居]", fg="green")
            total_found += len(neighbors)
        else:
            click.secho(" [無鄰居回報或不支援]", fg="yellow")

    click.echo(f"✅ LLDP 採集完畢，累計記錄 {total_found} 筆觀測資料。")


@cli.command("discover-topology")
@click.pass_context
def discover_topology_cmd(ctx: click.Context) -> None:
    """分析鄰居觀測資料，整合建立交換器互聯拓樸並自動推導連接埠角色。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    from ..topology.engine import TopologyEngine
    engine = TopologyEngine(repo)
    click.echo("🔄 正在整合交換器鄰居數據並推算校園有線網路拓樸...")
    stats = engine.reconcile_topology()

    click.echo("==================================================")
    click.echo(f" 拓樸推算完成：")
    click.echo(f"  - 建立/更新鏈路數: {stats['created']}")
    click.echo(f"  - 雙向確認高可信度鏈路: {stats['verified_links']}")
    click.echo("==================================================")


@cli.command("show-topology")
@click.pass_context
def show_topology_cmd(ctx: click.Context) -> None:
    """以表格形式展示目前已確認的交換器主幹互聯架構。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    links = repo.list_topology_links()
    click.echo("==========================================================================================================")
    click.echo(f" 校園交換器實體互聯拓樸總表 (共 {len(links)} 條確認線路)")
    click.echo("==========================================================================================================")
    header = f"{'本端交換器':<20} {'本端介面':<12} {'對端設備名稱':<25} {'對端管理 IP':<16} {'對端介面':<15} {'可信度'}"
    click.echo(header)
    click.echo("-" * 106)

    for l in links:
        local_name = f"{l['local_switch_name']} ({l['local_switch_ip']})"
        click.echo(
            f"{local_name[:19]:<20} "
            f"{(l['local_interface_name'] or l['local_if_index']):<12} "
            f"{(l['remote_switch_name'] or 'Unknown')[:24]:<25} "
            f"{(l['remote_mgmt_ip'] or l.get('resolved_remote_ip') or 'N/A'):<16} "
            f"{(l['remote_if_name'] or 'N/A'):<15} "
            f"{l['confidence_level']}"
        )
    click.echo("==========================================================================================================")


@cli.command("trace-mac")
@click.argument("mac")
@click.pass_context
def trace_mac_cmd(ctx: click.Context, mac: str) -> None:
    """沿著網路拓樸追蹤 MAC 位址的交換器傳遞路徑，並排除上行鏈路確認終端接入點。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    from ..topology.engine import TopologyEngine
    engine = TopologyEngine(repo)
    result = engine.trace_mac_path(mac)

    click.echo("==================================================")
    click.echo(f" MAC 拓樸路徑追蹤報告: {result['mac']}")
    click.echo("==================================================")
    click.echo(f" 定位狀態:     {result['status']}")
    click.echo(f" 判定原因:     {result['reason']}")

    click.echo("\n [交換器 FDB 學習路徑節點]")
    for idx, node in enumerate(result["path_nodes"], 1):
        role_tag = f"[{node['port_role']}]"
        click.echo(f"  {idx}. 交換器: {node['switch_name']} ({node['switch_ip']})")
        click.echo(f"     -> 連接埠: {node['port_name']} {role_tag} | VLAN: {node['vlan_id']}")
        click.echo(f"     -> 觀測時間: {format_ts(node['last_seen'])}")

    if result["final_location"]:
        fl = result["final_location"]
        click.secho("\n [🎯 判定最終實體接取端點]", fg="green", bold=True)
        click.echo(f"   接取交換器: {fl['switch_name']} ({fl['switch_ip']})")
        click.echo(f"   終端連接埠: {fl['port_name']} (Role: {fl['port_role']})")
    click.echo("==================================================")


@cli.command("list-alerts")
@click.option("--status", default=None, help="篩選狀態: OPEN, ACKNOWLEDGED, RESOLVED, SUPPRESSED, REOPENED")
@click.option("--severity", default=None, help="篩選嚴重等級: LOW, MEDIUM, HIGH, CRITICAL")
@click.option("--type", "event_type", default=None, help="篩選事件類型: DHCP_UNAUTHORIZED, SNMP_DOWN, UNREGISTERED_DEVICE 等")
@click.option("--limit", default=50, type=int, help="最多顯示筆數 (預設 50)")
@click.pass_context
def list_alerts_cmd(ctx: click.Context, status: str, severity: str, event_type: str, limit: int) -> None:
    """檢視目前告警事件清單。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    alerts = repo.list_alerts(status=status, severity=severity, event_type=event_type, limit=limit)
    click.echo("==========================================================================================================")
    click.echo(f" 校園網路安全與維運告警事件清單 (共 {len(alerts)} 筆)")
    click.echo("==========================================================================================================")
    header = f"{'ID':<5} {'狀態':<12} {'嚴重度':<10} {'類型':<22} {'次數':<6} {'最後發生時間':<20} {'事件標題'}"
    click.echo(header)
    click.echo("-" * 106)

    for a in alerts:
        status_color = "red" if a["status"] in ["OPEN", "REOPENED"] else ("yellow" if a["status"] == "ACKNOWLEDGED" else "green")
        stat_display = f"[{a['status']}]"
        click.echo(
            f"{a['event_id']:<5} "
            f"{click.style(stat_display[:11], fg=status_color):<20} "
            f"{(a.get('severity') or 'INFO'):<10} "
            f"{(a.get('event_type') or 'GENERAL')[:21]:<22} "
            f"{a.get('occurrence_count', 1):<6} "
            f"{format_ts(a.get('last_seen')):<20} "
            f"{a['title']}"
        )
    click.echo("==========================================================================================================")


@cli.command("show-alert")
@click.argument("event_id", type=int)
@click.pass_context
def show_alert_cmd(ctx: click.Context, event_id: int) -> None:
    """查看指定告警事件的詳細資訊、關聯證據與歷程。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    detail = repo.get_alert_detail(event_id)
    if not detail:
        click.secho(f"⚠️ 找不到 ID 為 #{event_id} 的告警事件。", fg="yellow")
        return

    click.echo("==================================================")
    click.echo(f" 告警事件詳情: #{detail['event_id']} - {detail['title']}")
    click.echo("==================================================")
    click.echo(f"   Event Key:      {detail['event_key']}")
    click.echo(f"   事件類型:       {detail['event_type']}")
    click.echo(f"   嚴重程度:       {detail['severity']}")
    click.echo(f"   目前狀態:       {detail['status']}")
    click.echo(f"   累計發生次數:   {detail['occurrence_count']} 次")
    click.echo(f"   首次發生:       {format_ts(detail['first_seen'])}")
    click.echo(f"   最後發生:       {format_ts(detail['last_seen'])}")
    click.echo(f"   詳細說明:       {detail.get('description') or '無'}")
    if detail.get("resolution_note"):
        click.echo(f"   處理註記:       {detail['resolution_note']}")

    click.echo("\n [歷次異常證據記錄]")
    evidence = detail.get("evidence", [])
    if not evidence:
        click.echo("   (無關聯證據)")
    else:
        for idx, ev in enumerate(evidence[:5], 1):
            click.echo(f"   {idx}. 類型: {ev['evidence_type']} | 記錄時間: {format_ts(ev['recorded_at'])}")
            if ev.get("source_ip"):
                click.echo(f"      來源 IP: {ev['source_ip']} | 用戶 MAC: {ev.get('client_mac') or 'N/A'}")
            if ev.get("raw_details"):
                click.echo(f"      原始資料: {ev['raw_details']}")

    click.echo("\n [狀態變更與處理歷程]")
    history = detail.get("history", [])
    if not history:
        click.echo("   (尚無手動狀態變更記錄)")
    else:
        for h in history:
            click.echo(f"   - [{format_ts(h['changed_at'])}] 由 {h['operator']} 從 {h['old_status']} 變更為 {h['new_status']} (備註: {h.get('note') or '無'})")
    click.echo("==================================================")


@cli.command("ack-alert")
@click.argument("event_id", type=int)
@click.option("--note", default="管理員已知悉並確認中", help="確認備註")
@click.pass_context
def ack_alert_cmd(ctx: click.Context, event_id: int, note: str) -> None:
    """將告警事件標記為已確認 (ACKNOWLEDGED)。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    ok, msg = repo.update_alert_status(event_id, "ACKNOWLEDGED", note=note)
    if ok:
        click.secho(f"✅ {msg}", fg="green")
    else:
        click.secho(f"❌ {msg}", fg="red")


@cli.command("resolve-alert")
@click.argument("event_id", type=int)
@click.option("--note", required=True, help="結案說明與排除原因")
@click.pass_context
def resolve_alert_cmd(ctx: click.Context, event_id: int, note: str) -> None:
    """手動將告警事件標記為已排除結案 (RESOLVED)。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    ok, msg = repo.update_alert_status(event_id, "RESOLVED", note=note)
    if ok:
        click.secho(f"✅ {msg}", fg="green")
    else:
        click.secho(f"❌ {msg}", fg="red")


@cli.command("suppress-alert")
@click.argument("event_id", type=int)
@click.option("--note", default="已確認為已知維護或測試行為", help="抑制原因")
@click.pass_context
def suppress_alert_cmd(ctx: click.Context, event_id: int, note: str) -> None:
    """將特定告警標記為抑制 (SUPPRESSED，不再發出通知)。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    ok, msg = repo.update_alert_status(event_id, "SUPPRESSED", note=note)
    if ok:
        click.secho(f"✅ {msg}", fg="yellow")
    else:
        click.secho(f"❌ {msg}", fg="red")


@cli.command("monitor-health")
@click.pass_context
def monitor_health_cmd(ctx: click.Context) -> None:
    """檢視監控模組 (DHCP Listener, SNMP Collector, Anomaly Engine) 的健康狀態。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    health_records = repo.get_all_monitoring_health()
    click.echo("=========================================================================================")
    click.echo(" 校園網路監控核心模組健康狀態")
    click.echo("=========================================================================================")
    click.echo(f"{'模組名稱':<20} {'運作狀態':<12} {'最後成功時間':<22} {'最後更新 / 錯誤訊息'}")
    click.echo("-" * 85)

    if not health_records:
        click.echo("目前尚無監控模組的執行紀錄（請先執行 netmon monitor 或 netmon detect-anomalies）。")
    else:
        for r in health_records:
            status_color = "green" if r["status"] == "RUNNING" else ("red" if r["status"] == "ERROR" else "yellow")
            err_msg = r.get("error_message") or "正常運作中"
            click.echo(
                f"{r['module_name']:<20} "
                f"{click.style(r['status'][:11], fg=status_color):<22} "
                f"{format_ts(r.get('last_success_time')):<22} "
                f"{err_msg}"
            )
    click.echo("=========================================================================================")


# ---------------------------------------------------------
# MVP-07: 告警與持續監控指令全集（支援 --stop 與 --module 參數）
# ---------------------------------------------------------

@cli.command("monitor")
@click.option("--stop", is_flag=True, help="停止所有背景監聽與監控服務，將所有模組狀態更新為 STOPPED。")
@click.option("--module", type=click.Choice(["all", "snmp", "anomaly", "dhcp"], case_sensitive=False), default="all", help="指定要啟動的特定監控模組 (all, snmp, anomaly, dhcp)。")
@click.pass_context
def monitor_cmd(ctx: click.Context, stop: bool, module: str) -> None:
    """啟動持續監控程序，支援 --stop 停止及 --module 分開啟動特定模組。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    db.init_schema()
    repo = NetworkRepository(db)

    # 1. 執行停止所有服務
    if stop:
        click.echo("🛑 正在發送停止訊號，準備關閉所有監控模組...")
        repo.record_monitoring_health("SNMP_COLLECTOR", "STOPPED")
        repo.record_monitoring_health("ANOMALY_ENGINE", "STOPPED")
        repo.record_monitoring_health("DHCP_LISTENER", "STOPPED")
        click.secho("✅ 所有監控模組已成功停止，狀態已更新為 STOPPED。", fg="green")
        return

    from ..monitor.service import MonitorService
    service = MonitorService(settings, repo)

    # 2. 若指定單獨啟動 dhcp 模組或設定檔 capture.enabled 為 True 且 module == all
    should_launch_gui_dhcp = (module.lower() == "dhcp") or (module.lower() == "all" and getattr(settings.capture, "enabled", False))

    if should_launch_gui_dhcp:
        click.echo("🌐 偵測到啟用 DHCP 封包擷取，正在自動彈出帶有彩色輸出的獨立子視窗執行 listen-dhcp...")
        if sys.platform == "win32":
            os.system("start cmd /k netmon listen-dhcp")
        else:
            subprocess.Popen(["netmon", "listen-dhcp"])

    # 3. 根據模組參數執行對應的背景常駐服務
    if module.lower() == "snmp":
        click.echo("🚀 正在啟動 [SNMP_COLLECTOR] 獨立監控循環...")
        service.start_snmp_only()
    elif module.lower() == "anomaly":
        click.echo("🚀 正在啟動 [ANOMALY_ENGINE] 獨立異常檢測循環...")
        service.start_anomaly_only()
    elif module.lower() == "dhcp":
        click.echo("✅ [DHCP_LISTENER] 已於獨立子視窗中啟動。主進程等待中...")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            click.echo("🛑 正在停止主進程...")
    else:
        click.echo("🚀 啟動完整持續監控服務 (SNMP_COLLECTOR 與 ANOMALY_ENGINE)...")
        service.start()


@cli.command("detect-anomalies")
@click.pass_context
def detect_anomalies_cmd(ctx: click.Context) -> None:
    """執行一次全網異常偵測掃描 (N01 ~ N04)。"""
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    db.init_schema()
    repo = NetworkRepository(db)

    from ..monitor.service import MonitorService
    service = MonitorService(settings, repo)
    click.echo("🔍 正在執行全網設備狀態與接入埠異常掃描...")
    service._run_snmp_cycle()
    service._run_fdb_device_scan()
    click.secho("✅ 異常掃描完成，請執行 netmon list-alerts 查看未結案告警。", fg="green")


@cli.command("alert-rules")
@click.pass_context
def alert_rules_cmd(ctx: click.Context) -> None:
    """顯示系統異常偵測規則清單 (N01 ~ N10) 與判定準則。"""
    rules = [
        {"id": "N01", "name": "未授權 DHCP Server", "level": "HIGH", "status": "啟用", "desc": "DHCP OFFER/ACK 來源不在授權 DHCP Server 清單"},
        {"id": "N02", "name": "DHCP Scope 不符", "level": "MEDIUM", "status": "啟用", "desc": "配發 IP 不符合群組設定之伺服器或網段規則"},
        {"id": "N03", "name": "SNMP 設備失聯", "level": "HIGH", "status": "啟用", "desc": "交換器連續 3 次 SNMP 輪詢逾時/失敗"},
        {"id": "N04", "name": "未登錄設備", "level": "LOW", "status": "啟用", "desc": "非 Uplink 接入埠學習到清冊中不存在的 MAC"},
        {"id": "N05", "name": "MAC 位址漂移", "level": "MEDIUM", "status": "啟用", "desc": "同一 MAC 短時間出現在不同接入埠 (結合拓樸排除骨幹)"},
        {"id": "N06", "name": "Uplink 連線異常", "level": "HIGH", "status": "啟用", "desc": "已確認之主幹 Uplink 埠狀態轉為 Down"},
        {"id": "N07", "name": "IP 位址衝突", "level": "HIGH", "status": "啟用", "desc": "同一 IP 位址被多個不同 MAC 位址同時使用"},
        {"id": "N08", "name": "人工驗證位置不符", "level": "MEDIUM", "status": "啟用", "desc": "目前 FDB 位置與網管人員實機驗證位置產生衝突"},
        {"id": "N09", "name": "拓樸異動", "level": "LOW", "status": "啟用", "desc": "交換器 LLDP/CDP 鄰居主幹連接關係發生變動"},
        {"id": "N10", "name": "DHCP Listener 異常", "level": "CRITICAL", "status": "啟用", "desc": "封包監聽程序停止、介面失效或持續報錯"},
    ]

    click.echo("==========================================================================================================")
    click.echo(" 系統異常偵測規則定義總表 (Alert Rules)")
    click.echo("==========================================================================================================")
    header = f"{'規則代碼':<10} {'規則名稱':<20} {'嚴重度':<10} {'模組狀態':<18} {'觸發條件與說明'}"
    click.echo(header)
    click.echo("-" * 106)
    for r in rules:
        click.echo(f"{r['id']:<10} {r['name']:<20} {r['level']:<10} {r['status']:<18} {r['desc']}")
    click.echo("==========================================================================================================")


@cli.command("alert-report")
@click.option("--output", "-o", default="alert_report.csv", help="匯出 CSV 報表路徑 (預設 alert_report.csv)")
@click.pass_context
def alert_report_cmd(ctx: click.Context, output: str) -> None:
    """匯出異常統計報表至終端機與 CSV 檔案。"""
    import csv
    settings = load_settings(ctx.obj["config_path"], ctx.obj["switches_path"])
    db = Database(settings.database.path)
    repo = NetworkRepository(db)

    stats = repo.get_alert_statistics_report()
    click.echo("==================================================")
    click.echo(" 校園網路異常事件摘要統計報表")
    click.echo("==================================================")
    click.echo(f"   總告警事件數:   {stats['total_alerts']} 筆")
    click.echo(f"   未結案事件數:   {stats['open_alerts']} 筆")
    click.echo(f"   已結案事件數:   {stats['resolved_alerts']} 筆")

    click.echo("\n [嚴重等級分佈]")
    for sev, cnt in stats["by_severity"].items():
        click.echo(f"   - {sev:<10}: {cnt} 件")

    click.echo("\n [告警類型分佈 (Top 5)]")
    for t, cnt in list(stats["by_type"].items())[:5]:
        click.echo(f"   - {t:<22}: {cnt} 件")
    click.echo("==================================================")

    try:
        with open(output, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "事件ID", "事件代碼 (Key)", "類型", "嚴重等級", "狀態",
                "標題", "說明", "首次發現時間", "最後發生時間", "累計次數",
                "結案說明", "結案時間"
            ])
            for a in stats["recent_alerts"]:
                writer.writerow([
                    a.get("event_id"), a.get("event_key"), a.get("event_type"),
                    a.get("severity"), a.get("status"), a.get("title"),
                    a.get("description"), format_ts(a.get("first_seen")),
                    format_ts(a.get("last_seen")), a.get("occurrence_count"),
                    a.get("resolution_note") or "", format_ts(a.get("resolved_at")) or ""
                ])
        click.secho(f"✅ 成功將詳細告警報表匯出至: {output}", fg="green")
    except Exception as e:
        click.secho(f"⚠️ 匯出 CSV 失敗: {e}", fg="red")