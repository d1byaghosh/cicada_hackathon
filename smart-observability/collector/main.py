import time
import platform

from host_probes import (
    collect_linux_auth_logs,
    collect_windows_security_logs,
    collect_bandwidth,
    collect_network_quality,
    collect_infrastructure_telemetry,
    collect_application_telemetry
)

from local import save_to_csv, initialize_csv

from config import (
    CSV_FILE,
    COLLECTION_INTERVAL,
    ENABLE_WINDOWS_LOGS,
    ENABLE_LINUX_LOGS,
    ENABLE_NETWORK_QUALITY,
    ENABLE_APPLICATION_MONITORING
)


# -------------------------------------------------
# HELPER: STANDARDIZE COLLECTOR OUTPUT
# -------------------------------------------------

def format_records(records, source):

    formatted = []

    for record in records:

        formatted.append({
            "source": source,
            "metric": record.get("metric", "Unknown"),
            "value": record.get("value", ""),
            "unit": record.get("unit", ""),
            "details": record.get("details", {})
        })

    return formatted


# -------------------------------------------------
# COLLECT ALL TELEMETRY
# -------------------------------------------------

def collect_all_telemetry():

    all_records = []

    collectors = []

    system = platform.system()

    # Security logs
    if system == "Windows" and ENABLE_WINDOWS_LOGS:

        collectors.append((
            "Windows Security",
            collect_windows_security_logs
        ))

    elif system == "Linux" and ENABLE_LINUX_LOGS:

        collectors.append((
            "Linux Security",
            collect_linux_auth_logs
        ))

    # Other telemetry
    collectors.extend([
        ("Bandwidth", collect_bandwidth),
        ("Infrastructure", collect_infrastructure_telemetry)
    ])

    if ENABLE_NETWORK_QUALITY:

        collectors.append((
            "Network Quality",
            collect_network_quality
        ))

    if ENABLE_APPLICATION_MONITORING:

        collectors.append((
            "Application",
            collect_application_telemetry
        ))

    # Execute each collector independently
    for source, collector in collectors:

        try:

            print(f"[INFO] Collecting {source}...")

            records = collector()

            formatted = format_records(records, source)

            all_records.extend(formatted)

            print(
                f"[SUCCESS] {source}: "
                f"{len(formatted)} records collected"
            )

        except Exception as error:

            print(f"[ERROR] {source}: {error}")

            all_records.append({
                "source": source,
                "metric": "Collection Error",
                "value": str(error),
                "unit": "",
                "details": {}
            })

    return all_records


# -------------------------------------------------
# MAIN MONITORING LOOP
# -------------------------------------------------

def main():

    print("=" * 55)
    print("       SYSTEM TELEMETRY MONITORING AGENT")
    print("=" * 55)

    initialize_csv(CSV_FILE)

    print(f"[INFO] CSV Location: {CSV_FILE}")

    print("[INFO] Monitoring Started")
    print("[INFO] Press CTRL+C to stop monitoring")

    try:

        while True:

            start_time = time.time()

            print("\n" + "=" * 55)

            print("Starting telemetry collection...")

            # Collect data
            telemetry = collect_all_telemetry()

            # Save data
            if telemetry:

                save_to_csv(
                    telemetry,
                    CSV_FILE
                )

            print(
                f"[INFO] Collection completed: "
                f"{len(telemetry)} records"
            )

            # Maintain configured interval between cycles
            elapsed = time.time() - start_time

            sleep_time = max(
                0,
                COLLECTION_INTERVAL - elapsed
            )

            print(
                f"[INFO] Next collection in "
                f"{sleep_time:.2f} seconds"
            )

            time.sleep(sleep_time)

    except KeyboardInterrupt:

        print("\n[INFO] Monitoring stopped by user")

    finally:

        print("[INFO] Telemetry agent terminated")


if __name__ == "__main__":

    main()