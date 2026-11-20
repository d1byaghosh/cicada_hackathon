import csv
import os
from datetime import datetime, timezone
import json

CSV_HEADERS = [
    "timestamp",
    "source",
    "metric",
    "value",
    "unit",
    "details"
]


def initialize_csv(file_path):

    directory = os.path.dirname(file_path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:

        with open(file_path, "w", newline="", encoding="utf-8") as file:

            writer = csv.DictWriter(
                file,
                fieldnames=CSV_HEADERS
            )

            writer.writeheader()

        print(f"[INFO] Created CSV file: {file_path}")


def save_to_csv(records, file_path):

    initialize_csv(file_path)

    timestamp = datetime.now(timezone.utc).isoformat()

    with open(file_path, "a", newline="", encoding="utf-8") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=CSV_HEADERS
        )

        for record in records:

            writer.writerow({
                "timestamp": record.get("timestamp", timestamp),
                "source": record.get("source", "Unknown"),
                "metric": record.get("metric", "Unknown"),
                "value": record.get("value", ""),
                "unit": record.get("unit", ""),
                "details": json.dumps(
                    record.get("details", {}),
                    default=str
                )
            })

    print(f"[INFO] Saved {len(records)} records to CSV")