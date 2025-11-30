#!/usr/bin/env python3
"""Test detector timeline parsing"""

import re
from datetime import datetime, timedelta

# Read log file
log_path = "scan_logs/scan_20251130_183055.log"

# Helper function to strip ANSI escape codes
def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# Regex patterns
finding_pattern = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+\[INFO\]\s+.*?Finding\s+\[(\w+)\]\s+(.+)',
    re.IGNORECASE
)

phase_pattern = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+\[INFO\]\s+Phase:\s+(.+)',
    re.IGNORECASE
)

scan_event_pattern = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+\[INFO\]\s+(Scan\s+(?:started|finished).+)',
    re.IGNORECASE
)

# Detector patterns
detector_start_pattern = re.compile(
    r'▶️\s+Стартира\s+(?:пасивен\s+)?(\w+)\s+за\s+(.+)',
    re.IGNORECASE
)

detector_result_pattern = re.compile(
    r'(?:✔️|ℹ️)\s+(\w+)\s+(?:намери|не намери)',
    re.IGNORECASE
)

timeline = []
last_timestamp = None
detector_offset = 0

print("Testing detector timeline parsing...")
print("=" * 60)

with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
    for line_num, line in enumerate(f, 1):
        clean_line = strip_ansi(line)
        
        # Check if line has timestamp
        timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', clean_line)
        if timestamp_match:
            try:
                last_timestamp = datetime.strptime(timestamp_match.group(1), "%Y-%m-%d %H:%M:%S")
                detector_offset = 0
            except ValueError:
                pass
        
        # Match detector start
        detector_start_match = detector_start_pattern.search(clean_line)
        if detector_start_match:
            detector_name = detector_start_match.group(1)
            target_url = detector_start_match.group(2).strip()
            
            if last_timestamp:
                detector_offset += 1
                estimated_time = last_timestamp + timedelta(seconds=detector_offset * 0.5)
                
                print(f"Line {line_num}: DETECTOR START - {detector_name} -> {target_url[:30]}")
                print(f"  Timestamp: {estimated_time.isoformat()}")
                timeline.append({
                    "detector": f"{detector_name} → {target_url[:30]}",
                    "timestamp": estimated_time.isoformat(),
                    "status": "started",
                    "type": "detector"
                })
            else:
                print(f"Line {line_num}: DETECTOR START (NO TIMESTAMP) - {detector_name}")
        
        # Match detector result
        detector_result_match = detector_result_pattern.search(clean_line)
        if detector_result_match:
            detector_name = detector_result_match.group(1)
            
            if last_timestamp:
                detector_offset += 0.2
                estimated_time = last_timestamp + timedelta(seconds=detector_offset)
                
                status = "completed" if "✔️" in line else "no_findings"
                print(f"Line {line_num}: DETECTOR RESULT - {detector_name} ({status})")
                timeline.append({
                    "detector": detector_name,
                    "timestamp": estimated_time.isoformat(),
                    "status": status,
                    "type": "detector_result"
                })

print("=" * 60)
print(f"\nTotal timeline events: {len(timeline)}")
print(f"\nFirst 10 events:")
for i, event in enumerate(timeline[:10], 1):
    print(f"{i}. {event['type']:15} | {event['detector'][:40]:40} | {event['status']}")
