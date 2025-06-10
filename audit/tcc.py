import os
import subprocess

def check_tcc_permissions():
    """Report which apps have sensitive TCC permissions (Screen Recording, Accessibility, etc)."""
    tcc_db = os.path.expanduser('~/Library/Application Support/com.apple.TCC/TCC.db')
    if not os.path.exists(tcc_db):
        return {
            "label": "TCC Privacy Permissions",
            "status": "OK",
            "info": ["TCC.db not found"],
            "tip": ""
        }
    # Services to check
    services = [
        ("Screen Recording", "kTCCServiceScreenCapture"),
        ("Input Monitoring", "kTCCServiceListenEvent"),
        ("Camera", "kTCCServiceCamera"),
        ("Microphone", "kTCCServiceMicrophone"),
        ("Location", "kTCCServiceLocation"),
        ("Full Disk Access", "kTCCServiceSystemPolicyAllFiles"),
        ("Automation", "kTCCServiceAppleEvents"),
        ("Accessibility", "kTCCServiceAccessibility"),
    ]
    results = []
    for label, service in services:
        try:
            result = subprocess.run([
                'sqlite3', tcc_db,
                f"SELECT client FROM access WHERE service='{service}' AND allowed=1;"
            ], capture_output=True, text=True)
            apps = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
            if apps:
                results.append(f"{label}: {', '.join(apps)}")
        except Exception as e:
            results.append(f"{label}: ERROR: {e}")
    tip = "Tip: Review which apps have sensitive permissions. Remove any you don't recognize in System Preferences > Security & Privacy."
    return {
        "label": "TCC Privacy Permissions",
        "status": "ALERT" if results else "OK",
        "info": results if results else ["No apps with sensitive permissions found."],
        "tip": tip
    } 