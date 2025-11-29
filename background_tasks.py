"""
Background tasks for monitoring scan status and updating database.
"""
import time
import psutil
from datetime import datetime
from threading import Thread
from database import get_db_session
from models import Scan, ScanStatus


def monitor_scan_status(job_id: str, pid: int):
    """
    Background thread to monitor scan process and update database.
    Checks if process is still running and updates status when complete.
    """
    def check_process():
        max_wait = 3600  # Max 1 hour
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                proc = psutil.Process(pid)
                if not proc.is_running():
                    # Process finished
                    with get_db_session() as db:
                        scan = db.query(Scan).filter(Scan.job_id == job_id).first()
                        if scan and scan.status == ScanStatus.RUNNING:
                            scan.status = ScanStatus.COMPLETED
                            scan.completed_at = datetime.now()
                            db.commit()
                    break
                time.sleep(5)  # Check every 5 seconds
            except psutil.NoSuchProcess:
                # Process already terminated
                with get_db_session() as db:
                    scan = db.query(Scan).filter(Scan.job_id == job_id).first()
                    if scan and scan.status == ScanStatus.RUNNING:
                        scan.status = ScanStatus.COMPLETED
                        scan.completed_at = datetime.now()
                        db.commit()
                break
            except Exception as e:
                print(f"Error monitoring scan {job_id}: {e}")
                time.sleep(10)
    
    thread = Thread(target=check_process, daemon=True)
    thread.start()


def parse_vulnerability_count(report_path: str) -> int:
    """
    Parse HTML report to count vulnerabilities.
    Looks for vulnerability sections in the report.
    """
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Count different vulnerability markers
        count = 0
        
        # Common patterns in reports
        patterns = [
            '🔴 CRITICAL',
            '🟠 HIGH',
            '🟡 MEDIUM',
            '⚠️ Potential',
            'Vulnerability:',
            'Finding:',
        ]
        
        for pattern in patterns:
            count += content.count(pattern)
        
        return count
    except Exception as e:
        print(f"Error parsing report {report_path}: {e}")
        return 0
