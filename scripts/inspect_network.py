#!/usr/bin/env python3
"""Inspect Linux network sockets, TCP states, listen backlogs, interface drops, /proc/net/snmp, and /proc/net/netstat."""
import argparse
import json
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def parse_proc_net_tcp(proc_root: Path) -> Dict[str, Any]:
    state_counts = {name: 0 for name in TCP_STATES.values()}
    backlog_sockets: List[Dict[str, Any]] = []

    for fname in ("tcp", "tcp6"):
        fpath = proc_root / "net" / fname
        if not fpath.exists():
            continue
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            st_hex = parts[3].upper()
            st_name = TCP_STATES.get(st_hex, f"UNKNOWN_{st_hex}")
            state_counts[st_name] = state_counts.get(st_name, 0) + 1
            if ":" in parts[4]:
                tx_hex, rx_hex = parts[4].split(":", 1)
                try:
                    tx_q = int(tx_hex, 16)
                    rx_q = int(rx_hex, 16)
                    if rx_q > 0 or tx_q > 0:
                        backlog_sockets.append({
                            "table": fname,
                            "local_address": parts[1],
                            "state": st_name,
                            "tx_queue": tx_q,
                            "rx_queue": rx_q,
                        })
                except ValueError:
                    pass
    return {"state_counts": state_counts, "queued_sockets": backlog_sockets}


def parse_proc_net_dev(proc_root: Path) -> Dict[str, Dict[str, int]]:
    dev_path = proc_root / "net" / "dev"
    interfaces: Dict[str, Dict[str, int]] = {}
    if not dev_path.exists():
        return interfaces
    lines = dev_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[2:]:
        if ":" not in line:
            continue
        iface, rest = line.split(":", 1)
        cols = rest.strip().split()
        if len(cols) >= 16:
            interfaces[iface.strip()] = {
                "rx_bytes": int(cols[0]),
                "rx_packets": int(cols[1]),
                "rx_errs": int(cols[2]),
                "rx_drop": int(cols[3]),
                "tx_bytes": int(cols[8]),
                "tx_packets": int(cols[9]),
                "tx_errs": int(cols[10]),
                "tx_drop": int(cols[11]),
            }
    return interfaces


def parse_paired_header_file(fpath: Path) -> Dict[str, Dict[str, int]]:
    """Parse two-line header/value MIB files such as /proc/net/snmp and /proc/net/netstat."""
    out: Dict[str, Dict[str, int]] = {}
    if not fpath.exists():
        return out
    lines = [l.strip() for l in fpath.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    idx = 0
    while idx + 1 < len(lines):
        h_parts = lines[idx].split()
        v_parts = lines[idx + 1].split()
        if h_parts and v_parts and h_parts[0] == v_parts[0] and len(h_parts) == len(v_parts):
            proto = h_parts[0].rstrip(":")
            section: Dict[str, int] = {}
            for k, v in zip(h_parts[1:], v_parts[1:]):
                if v.lstrip("-").isdigit():
                    section[k] = int(v)
            out[proto] = section
            idx += 2
        else:
            idx += 1
    return out


def inspect_network(proc_root: Path) -> Dict[str, Any]:
    warnings: List[str] = []
    errors: List[str] = []
    findings: List[Dict[str, Any]] = []
    recommendations: List[str] = []

    if not proc_root.exists():
        return {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": {"system": platform.system(), "release": platform.release()},
            "tool_versions": {"python": platform.python_version()},
            "findings": [],
            "metrics": {},
            "warnings": [],
            "recommendations": [],
            "errors": [f"Proc root does not exist: {proc_root}"],
        }

    tcp_info = parse_proc_net_tcp(proc_root)
    interfaces = parse_proc_net_dev(proc_root)
    snmp = parse_paired_header_file(proc_root / "net" / "snmp")
    netstat = parse_paired_header_file(proc_root / "net" / "netstat")
    states = tcp_info["state_counts"]
    status = "ok"

    close_wait = states.get("CLOSE_WAIT", 0)
    time_wait = states.get("TIME_WAIT", 0)
    syn_recv = states.get("SYN_RECV", 0)

    if close_wait >= 50:
        status = "warning" if close_wait < 200 else "critical"
        findings.append({
            "id": "NET-TCP-001",
            "category": "network",
            "severity": "high" if close_wait >= 200 else "medium",
            "classification": "measured",
            "title": f"High CLOSE_WAIT socket accumulation ({close_wait} sockets)",
            "evidence": {"close_wait_count": close_wait, "state_counts": states},
            "likely_causes": [
                "Application failing to call close() on sockets after remote peer FIN disconnect",
                "Worker thread starvation preventing socket cleanup"
            ],
            "confidence": "high",
            "recommendation": "Audit application connection pool lifecycle and ensure HTTP/DB client connections are closed in finally/defer blocks."
        })
        recommendations.append("Fix application socket leak indicated by elevated CLOSE_WAIT connections.")

    if time_wait >= 2000:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "NET-TCP-002",
            "category": "network",
            "severity": "medium",
            "classification": "measured",
            "title": f"Elevated TIME_WAIT socket count ({time_wait} sockets)",
            "evidence": {"time_wait_count": time_wait},
            "likely_causes": ["High rate of short-lived outbound TCP connections without keep-alive pooling"],
            "confidence": "high",
            "recommendation": "Enable HTTP keep-alive and database connection pooling to reuse TCP sockets."
        })

    if syn_recv >= 100:
        status = "warning"
        findings.append({
            "id": "NET-TCP-003",
            "category": "network",
            "severity": "high",
            "classification": "measured",
            "title": f"Elevated SYN_RECV backlog ({syn_recv} sockets)",
            "evidence": {"syn_recv_count": syn_recv},
            "likely_causes": ["Accept queue saturation on listening service or inbound SYN flood"],
            "confidence": "high",
            "recommendation": "Check net.core.somaxconn, application listen backlog, and worker accept loop latency."
        })

    # Evaluate /proc/net/snmp TCP retransmission ratio and UDP buffer errors
    tcp_mib = snmp.get("Tcp", {})
    out_segs = tcp_mib.get("OutSegs", 0)
    retrans_segs = tcp_mib.get("RetransSegs", 0)
    retrans_pct = round((retrans_segs * 100.0 / out_segs), 3) if out_segs > 0 else 0.0
    if retrans_pct >= 1.0 and retrans_segs >= 100:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "NET-SNMP-RETRANS",
            "category": "network_retransmissions",
            "severity": "high" if retrans_pct >= 5.0 else "medium",
            "classification": "measured",
            "title": f"Elevated TCP segment retransmission rate ({retrans_pct}%: {retrans_segs}/{out_segs} segments)",
            "evidence": {
                "out_segs_cumulative": out_segs,
                "retrans_segs_cumulative": retrans_segs,
                "retrans_pct": retrans_pct,
                "estab_resets": tcp_mib.get("EstabResets", 0),
            },
            "likely_causes": ["Network congestion, NIC ring buffer drops, or cloud virtual switch bandwidth policing"],
            "confidence": "high",
            "recommendation": "Check interface tx_drop/rx_drop counters and TCP congestion control settings."
        })
        recommendations.append("Investigate network path packet loss driving TCP retransmissions.")

    udp_mib = snmp.get("Udp", {})
    udp_rcvbuf_errs = udp_mib.get("RcvbufErrors", 0)
    if udp_rcvbuf_errs > 0:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "NET-SNMP-UDPBUF",
            "category": "network_udp",
            "severity": "medium",
            "classification": "measured",
            "title": f"UDP socket receive buffer drops recorded (RcvbufErrors={udp_rcvbuf_errs})",
            "evidence": {"udp_mib": udp_mib},
            "likely_causes": ["net.core.rmem_max too small for burst UDP traffic (e.g., DNS/QUIC/StatsD)"],
            "confidence": "high",
            "recommendation": "Increase net.core.rmem_max or scale UDP reader threads."
        })

    # Evaluate /proc/net/netstat TcpExt ListenOverflows / ListenDrops
    tcp_ext = netstat.get("TcpExt", {})
    listen_overflows = tcp_ext.get("ListenOverflows", 0)
    listen_drops = tcp_ext.get("ListenDrops", 0)
    if listen_overflows > 0 or listen_drops > 0:
        status = "warning" if listen_overflows < 100 else "critical"
        findings.append({
            "id": "NET-NETSTAT-LISTEN",
            "category": "listen_backlog",
            "severity": "high",
            "classification": "measured",
            "title": f"TCP listen queue overflows detected (ListenOverflows={listen_overflows}, ListenDrops={listen_drops})",
            "evidence": {
                "ListenOverflows": listen_overflows,
                "ListenDrops": listen_drops,
                "TCPSynRetrans": tcp_ext.get("TCPSynRetrans", 0),
                "TCPTimeouts": tcp_ext.get("TCPTimeouts", 0),
            },
            "likely_causes": [
                "Application accept() loop is stalled or net.core.somaxconn / net.ipv4.tcp_max_syn_backlog is undersized"
            ],
            "confidence": "high",
            "recommendation": "Raise net.core.somaxconn and application listen() backlog parameter, and check worker CPU throttling."
        })
        recommendations.append("Remediate TCP accept queue saturation indicated by TcpExt.ListenOverflows.")

    high_queue = [s for s in tcp_info["queued_sockets"] if s["rx_queue"] >= 4096 or s["tx_queue"] >= 65536]
    if high_queue:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "NET-QUEUE-001",
            "category": "network",
            "severity": "medium",
            "classification": "measured",
            "title": f"Detected {len(high_queue)} sockets with elevated Recv-Q or Send-Q buffers",
            "evidence": {"queued_sockets": high_queue[:10]},
            "likely_causes": ["Slow application reader (high Recv-Q) or congested downstream receiver (high Send-Q)"],
            "confidence": "high",
            "recommendation": "Inspect stalled reader/writer processes holding queued sockets."
        })

    total_drops = sum(v["rx_drop"] + v["tx_drop"] + v["rx_errs"] + v["tx_errs"] for v in interfaces.values())
    if total_drops > 100:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "NET-IFACE-001",
            "category": "network",
            "severity": "medium",
            "classification": "measured",
            "title": f"Network interface packet drops or errors detected (total={total_drops})",
            "evidence": {"interfaces": interfaces},
            "likely_causes": ["Ring buffer exhaustion, NIC IRQ saturation, or virtual bridge policing"],
            "confidence": "medium",
            "recommendation": "Inspect per-interface rx_drop/tx_drop counts and verify ring buffer sizing."
        })

    if not findings:
        findings.append({
            "id": "NET-OK-001",
            "category": "network",
            "severity": "info",
            "classification": "measured",
            "title": "Network socket states, queues, SNMP/Netstat MIBs, and interface counters healthy",
            "evidence": {"state_counts": states, "interface_count": len(interfaces)},
            "likely_causes": ["No socket backlog, listen overflow, or packet drop anomalies observed"],
            "confidence": "high",
            "recommendation": "No immediate network stack remediation needed."
        })

    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {"system": platform.system(), "release": platform.release()},
        "tool_versions": {"python": platform.python_version(), "ss_available": shutil.which("ss") is not None},
        "findings": findings,
        "metrics": {
            "metric_semantics": {
                "tcp_state_counts_and_queues": "instantaneous",
                "interfaces_snmp_and_netstat": "cumulative_since_boot",
            },
            "tcp_state_counts": states,
            "queued_sockets": tcp_info["queued_sockets"],
            "interfaces": interfaces,
            "snmp": snmp,
            "netstat": netstat,
            "tcp_retransmission_pct": retrans_pct,
        },
        "warnings": warnings,
        "recommendations": recommendations or ["No immediate network stack remediation needed."],
        "errors": errors,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect Linux network sockets, interfaces, /proc/net/snmp, and /proc/net/netstat.")
    parser.add_argument("--proc-root", default="/proc", help="Path to /proc filesystem")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args(argv)

    payload = inspect_network(Path(args.proc_root))
    if payload["status"] == "error":
        print(json.dumps(payload), file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
