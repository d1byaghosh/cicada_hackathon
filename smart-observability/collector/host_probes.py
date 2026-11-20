import os
import re
import time
import platform
import requests
import psutil
import json

from icmplib import ping

# Windows-specific imports
if platform.system() == "Windows":
    import win32evtlog

from config import (
    MAX_SECURITY_EVENTS,
    NETWORK_TARGET,
    APPLICATION_BASE_URL,
    LINUX_AUTH_LOG,
    ENABLE_WINDOWS_LOGS,
    ENABLE_LINUX_LOGS,
    ENABLE_NETWORK_QUALITY,
    ENABLE_APPLICATION_MONITORING
)


# -------------------------------------------------
# 1. LINUX SECURITY LOGS
# -------------------------------------------------

def collect_linux_auth_logs(log_file=LINUX_AUTH_LOG):

    security_events = []

    patterns = [
        r"Failed password",
        r"Invalid user",
        r"authentication failure"
    ]

    if not os.path.exists(log_file):
        return security_events

    try:
        with open(log_file, "r", errors="replace") as file:

            for line in file:

                if any(
                    re.search(pattern, line, re.IGNORECASE)
                    for pattern in patterns
                ):

                    security_events.append({
                        "metric": "Security Event",
                        "value": "Failed Login",
                        "details": {
                            "raw_log": line.strip()
                        }
                    })

    except (PermissionError, OSError) as error:
        print(f"[ERROR] Linux logs: {error}")

    return security_events


# -------------------------------------------------
# 2. WINDOWS SECURITY LOGS
# -------------------------------------------------

def collect_windows_security_logs(max_events=MAX_SECURITY_EVENTS):

    security_events = []

    if platform.system() != "Windows":
        return security_events

    server = "localhost"
    log_type = "Security"

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ |
        win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    handle = None

    try:

        handle = win32evtlog.OpenEventLog(server, log_type)

        while len(security_events) < max_events:

            events = win32evtlog.ReadEventLog(
                handle, flags, 0
            )

            if not events:
                break

            for event in events:

                event_id = event.EventID & 0xFFFF

                event_types = {
                    4624: "Successful Login",
                    4625: "Failed Login",
                    4648: "Explicit Credentials",
                    4720: "User Created"
                }

                if event_id in event_types:

                    security_events.append({
                        "metric": "Security Event",
                        "value": event_types[event_id],
                        "details": {
                            "event_id": event_id,
                            "timestamp": event.TimeGenerated.isoformat(),
                            "computer": event.ComputerName,
                            "event_record_id": event.RecordNumber,
                            "details": list(
                                event.StringInserts or []
                            )
                        }
                    })

                if len(security_events) >= max_events:
                    break

    except Exception as error:
        print(f"[ERROR] Windows logs: {error}")

    finally:

        if handle is not None:
            win32evtlog.CloseEventLog(handle)

    return security_events


# -------------------------------------------------
# 3. BANDWIDTH MONITORING
# -------------------------------------------------

def collect_bandwidth():

    before = psutil.net_io_counters()

    time.sleep(1)

    after = psutil.net_io_counters()

    sent_mbps = (
        (after.bytes_sent - before.bytes_sent) * 8
    ) / 1_000_000

    received_mbps = (
        (after.bytes_recv - before.bytes_recv) * 8
    ) / 1_000_000

    return [
        {
            "metric": "Upload Rate",
            "value": round(sent_mbps, 3),
            "unit": "Mbps"
        },
        {
            "metric": "Download Rate",
            "value": round(received_mbps, 3),
            "unit": "Mbps"
        }
    ]


# -------------------------------------------------
# 4. NETWORK QUALITY MONITORING
# -------------------------------------------------

def collect_network_quality(target=NETWORK_TARGET):

    try:

        host = ping(
            target,
            count=5,
            interval=0.2,
            timeout=2,
            privileged=False
        )

        return [
            {
                "metric": "Connectivity",
                "value": "UP" if host.is_alive else "DOWN"
            },
            {
                "metric": "Latency",
                "value": round(host.avg_rtt, 2),
                "unit": "ms"
            },
            {
                "metric": "Packet Loss",
                "value": round(host.packet_loss * 100, 2),
                "unit": "%"
            },
            {
                "metric": "Jitter",
                "value": round(host.jitter, 2),
                "unit": "ms"
            },
            {
                "metric": "Packets Sent",
                "value": host.packets_sent
            },
            {
                "metric": "Packets Received",
                "value": host.packets_received
            }
        ]

    except Exception as error:

        return [{
            "metric": "Network Monitoring Error",
            "value": str(error)
        }]


# -------------------------------------------------
# 5. INFRASTRUCTURE MONITORING
# -------------------------------------------------

def collect_infrastructure_telemetry():

    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()

    disk = psutil.disk_usage(os.path.abspath(os.sep))

    network = psutil.net_io_counters()

    return [
        {
            "metric": "CPU Usage",
            "value": cpu,
            "unit": "%"
        },
        {
            "metric": "Total RAM",
            "value": round(memory.total / (1024 ** 3), 2),
            "unit": "GB"
        },
        {
            "metric": "Used RAM",
            "value": round(memory.used / (1024 ** 3), 2),
            "unit": "GB"
        },
        {
            "metric": "RAM Usage",
            "value": memory.percent,
            "unit": "%"
        },
        {
            "metric": "Total Disk",
            "value": round(disk.total / (1024 ** 3), 2),
            "unit": "GB"
        },
        {
            "metric": "Used Disk",
            "value": round(disk.used / (1024 ** 3), 2),
            "unit": "GB"
        },
        {
            "metric": "Disk Usage",
            "value": disk.percent,
            "unit": "%"
        },
        {
            "metric": "Bytes Sent",
            "value": network.bytes_sent,
            "unit": "bytes"
        },
        {
            "metric": "Bytes Received",
            "value": network.bytes_recv,
            "unit": "bytes"
        }
    ]


# -------------------------------------------------
# 6. APPLICATION MONITORING
# -------------------------------------------------

def collect_application_telemetry(
    base_url=APPLICATION_BASE_URL,
    timeout=10
):

    telemetry = []

    endpoints = {
        "Health": "/health",
        "Logs": "/api/logs",
        "Error Counts": "/api/metrics/errors",
        "Response Time": "/api/status"
    }

    # Health
    try:

        response = requests.get(
            base_url + endpoints["Health"],
            timeout=timeout
        )

        telemetry.append({
            "metric": "Application Health",
            "value": response.status_code,
            "unit": "HTTP Status"
        })

    except requests.RequestException:

        telemetry.append({
            "metric": "Application Health",
            "value": "UNAVAILABLE"
        })

    # Logs
    try:

        response = requests.get(
            base_url + endpoints["Logs"],
            timeout=timeout
        )

        response.raise_for_status()

        telemetry.append({
            "metric": "Application Logs",
            "value": "Available",
            "details": response.json()
        })

    except (requests.RequestException, ValueError) as error:

        telemetry.append({
            "metric": "Application Logs",
            "value": "UNAVAILABLE",
            "details": {"error": str(error)}
        })

    # Error counts
    try:

        response = requests.get(
            base_url + endpoints["Error Counts"],
            timeout=timeout
        )

        response.raise_for_status()

        telemetry.append({
            "metric": "Application Error Counts",
            "value": "Available",
            "details": response.json()
        })

    except (requests.RequestException, ValueError) as error:

        telemetry.append({
            "metric": "Application Error Counts",
            "value": "UNAVAILABLE",
            "details": {"error": str(error)}
        })

    # Response time
    try:

        start = time.perf_counter()

        response = requests.get(
            base_url + endpoints["Response Time"],
            timeout=timeout
        )

        elapsed = time.perf_counter() - start

        telemetry.append({
            "metric": "Application Response Time",
            "value": round(elapsed * 1000, 2),
            "unit": "ms"
        })

    except requests.RequestException:

        telemetry.append({
            "metric": "Application Response Time",
            "value": "UNAVAILABLE"
        })

    return telemetry