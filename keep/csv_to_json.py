
import csv
import json
import uuid
import hashlib

from pathlib import Path
from datetime import datetime, timezone


# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(r"D:\cicada-2026")

INPUT_FILE = BASE_DIR / "data.csv"
OUTPUT_FILE = BASE_DIR / "normalized_telemetry.json"

COLLECTOR_ID = "collector-01"
HOST_ID = "host-a81f2"

COLLECTOR_VERSION = "1.0.0"
SOURCE_TIMEZONE = "Asia/Kolkata"

COLLECTION_STATUS = "SUCCESS"
COLLECTOR_STATUS = "ONLINE"

# Reserved for future Logistic Regression model
SECURITY_STATUS = ""


# ==================================================
# TIMESTAMP CONVERSION
# ==================================================

def convert_to_utc(timestamp):

    try:
        dt = datetime.fromisoformat(timestamp.strip())

        if dt.tzinfo is None:
            raise ValueError("Timestamp must contain timezone information")

        return dt.astimezone(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")

    except (ValueError, AttributeError) as error:
        raise ValueError(
            f"Invalid timestamp: {timestamp}. {error}"
        )


# ==================================================
# VALUE PARSING
# ==================================================

def parse_value(value):

    if value is None or value.strip() == "":
        return None

    try:
        number = float(value)

        if number.is_integer():
            return int(number)

        return number

    except ValueError:
        return value


# ==================================================
# DETAILS PARSING
# ==================================================

def parse_details(details):

    if not details or not details.strip():
        return {}

    try:
        parsed = json.loads(details)

        if isinstance(parsed, dict):
            return parsed

        return {"value": parsed}

    except json.JSONDecodeError:
        return {"raw_details": details}


# ==================================================
# DETERMINISTIC EVENT ID
# ==================================================

def generate_event_id(row, row_number):

    row_content = json.dumps(
        row,
        sort_keys=True,
        ensure_ascii=False
    )

    unique_string = (
        f"{COLLECTOR_ID}:"
        f"{row_number}:"
        f"{row_content}"
    )

    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            unique_string
        )
    )


# ==================================================
# CSV VALIDATION
# ==================================================

def validate_csv_headers(reader):

    required_columns = {
        "timestamp",
        "source",
        "metric",
        "value",
        "unit",
        "details"
    }

    actual_columns = set(reader.fieldnames or [])

    missing = required_columns - actual_columns

    if missing:
        raise ValueError(
            f"Missing required CSV columns: {missing}"
        )


# ==================================================
# MAIN CONVERSION FUNCTION
# ==================================================

def convert_csv_to_json():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"CSV file not found: {INPUT_FILE}"
        )

    records = []

    skipped_records = 0

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        validate_csv_headers(reader)

        for row_number, row in enumerate(reader, start=1):

            try:

                timestamp = row["timestamp"].strip()

                if not timestamp:
                    raise ValueError("Timestamp is empty")

                utc_timestamp = convert_to_utc(timestamp)

                record = {

                    # Original CSV fields
                    "timestamp": timestamp,
                    "source": row["source"],
                    "metric": row["metric"],
                    "value": parse_value(row["value"]),
                    "unit": row["unit"] or "",
                    "details": parse_details(row["details"]),

                    # Identification
                    "event_id": generate_event_id(
                        row,
                        row_number
                    ),

                    "collector_id": COLLECTOR_ID,
                    "host_id": HOST_ID,

                    # Time information
                    "event_time_utc": utc_timestamp,
                    "source_timezone": SOURCE_TIMEZONE,

                    # Collector information
                    "collection_status": COLLECTION_STATUS,
                    "collector_status": COLLECTOR_STATUS,
                    "collector_version": COLLECTOR_VERSION,

                    # Future ML prediction
                    "security_status": SECURITY_STATUS
                }

                records.append(record)

            except (ValueError, TypeError, KeyError) as error:

                skipped_records += 1

                print(
                    f"[WARNING] Skipping row {row_number}: {error}"
                )

    # Write output safely
    temporary_file = OUTPUT_FILE.with_suffix(".tmp")

    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as json_file:

        json.dump(
            records,
            json_file,
            indent=4,
            ensure_ascii=False
        )

    temporary_file.replace(OUTPUT_FILE)

    # Summary
    print("\n================================")
    print(" CSV TO JSON CONVERSION COMPLETE")
    print("================================")

    print(f"Input file     : {INPUT_FILE}")
    print(f"Output file    : {OUTPUT_FILE}")
    print(f"Records saved  : {len(records)}")
    print(f"Records skipped: {skipped_records}")

    print("================================\n")


# ==================================================
# EXECUTION
# ==================================================

if __name__ == "__main__":

    convert_csv_to_json()
