import subprocess, sys, time, os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5000"


def ensure_server():
    import requests
    try:
        r = requests.get(BASE + "/", timeout=2)
        if r.status_code == 200:
            return True
    except Exception:
        pass
    # Start server if not running
    env = os.environ.copy()
    venv_python = ROOT / "venv" / "bin" / "python"
    if not venv_python.exists():
        print("venv not found at ./venv")
        return False
    log = ROOT / "tmp_test_server.log"
    if log.exists():
        log.unlink()
    proc = subprocess.Popen([str(venv_python), "-m", "uvicorn", "webapp:app", "--host", "127.0.0.1", "--port", "5000"], cwd=str(ROOT), stdout=open(log, "w"), stderr=subprocess.STDOUT)
    time.sleep(2)
    # Probe again
    try:
        for _ in range(10):
            r = requests.get(BASE + "/", timeout=2)
            if r.status_code == 200:
                return True
            time.sleep(0.5)
    except Exception:
        pass
    return False


def ensure_test_fixtures():
    # Prepare test user + completed scan in DB
    import sys
    sys.path.insert(0, str(ROOT))
    from database import engine
    from models import Base, User, Scan, ScanStatus, Subscription, SubscriptionTierEnum, SubscriptionStatus
    from sqlalchemy.orm import sessionmaker
    from datetime import datetime
    from auth import hash_password

    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    s = Session()

    user = s.query(User).filter(User.email == "test@example.com").first()
    if not user:
        user = User(email="test@example.com", password_hash=hash_password("password"), is_verified=True)
        s.add(user)
        s.commit()
    else:
        if not user.is_verified:
            user.is_verified = True
            s.commit()

    # Ensure ENTERPRISE subscription to avoid rate/concurrency limits
    sub = s.query(Subscription).filter(Subscription.user_id == user.id).first()
    if not sub:
        sub = Subscription(
            user_id=user.id,
            tier=SubscriptionTierEnum.ENTERPRISE,
            status=SubscriptionStatus.ACTIVE,
        )
        s.add(sub)
        s.commit()
    else:
        if sub.tier != SubscriptionTierEnum.ENTERPRISE or sub.status != SubscriptionStatus.ACTIVE:
            sub.tier = SubscriptionTierEnum.ENTERPRISE
            sub.status = SubscriptionStatus.ACTIVE
            s.commit()

    # Ensure a completed scan with timeline-rich log
    job_id = "test_scan_001"
    scan = s.query(Scan).filter(Scan.job_id == job_id).first()
    if not scan:
        scan = Scan(
            user_id=user.id,
            job_id=job_id,
            mode="recon",
            target="httpbin.org",
            status=ScanStatus.COMPLETED,
            log_path=str(ROOT / "scan_logs" / "scan_20251130_184347.log"),
            created_at=datetime.utcnow(),
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        s.add(scan)
        s.commit()
    s.close()


def main():
    # Install requests if not available
    try:
        import requests  # noqa
    except Exception:
        print("Please run in venv with requests installed")
        sys.exit(1)

    print("Ensuring server...")
    if not ensure_server():
        print("Server failed to start")
        sys.exit(1)

    print("Ensuring fixtures...")
    ensure_test_fixtures()

    print("Running API E2E...")
    api = subprocess.run([sys.executable, str(ROOT / "tests" / "test_api_e2e.py")], capture_output=True, text=True)
    print(api.stdout)
    if api.returncode != 0:
        print(api.stderr)
        sys.exit(api.returncode)

    print("Running UI E2E...")
    ui = subprocess.run([sys.executable, str(ROOT / "tests" / "test_ui_e2e.py")], capture_output=True, text=True)
    print(ui.stdout)
    if ui.returncode != 0:
        print(ui.stderr)
        sys.exit(ui.returncode)

    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
