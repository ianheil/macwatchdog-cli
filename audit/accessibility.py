import os
import subprocess

def check_accessibility_apps():
    """Return a list of apps with Accessibility or Full Disk Access permissions."""
    try:
        # Check TCC.db for Accessibility and Full Disk Access
        tcc_db = os.path.expanduser('~/Library/Application Support/com.apple.TCC/TCC.db')
        if not os.path.exists(tcc_db):
            return {"label": "Accessibility/Full Disk Access", "status": "OK", "info": ["TCC.db not found"], "tip": ""}
        result = subprocess.run([
            'sqlite3', tcc_db,
            "SELECT client, service FROM access WHERE service IN ('kTCCServiceAccessibility', 'kTCCServiceSystemPolicyAllFiles') AND allowed=1;"
        ], capture_output=True, text=True)
        apps = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
        tip = "Tip: Only trusted apps should have Accessibility or Full Disk Access. Review and remove any unknown apps from System Preferences > Security & Privacy."
        return {
            "label": "Accessibility/Full Disk Access",
            "status": "ALERT" if apps else "OK",
            "info": apps if apps else ["No apps with Accessibility or Full Disk Access found"],
            "tip": tip
        }
    except Exception as e:
        return {"label": "Accessibility/Full Disk Access", "status": "ERROR", "info": [str(e)], "tip": ""} 