import os

SENSITIVE_PATHS = [
    '/Library/LaunchAgents',
    '/Library/LaunchDaemons',
    os.path.expanduser('~/Library/LaunchAgents'),
    '/etc',
    '/usr/local/bin',
    '/usr/local/sbin',
]

def check_world_writable():
    """Return a list of world-writable files in sensitive locations."""
    suspicious = []
    for path in SENSITIVE_PATHS:
        if os.path.exists(path):
            for f in os.listdir(path):
                full_path = os.path.join(path, f)
                try:
                    mode = os.stat(full_path).st_mode
                    if mode & 0o002:
                        suspicious.append(full_path)
                except Exception:
                    continue
    tip = "Tip: World-writable files in sensitive locations can be abused by malware or attackers. Remove or restrict permissions on anything you don't recognize."
    return {
        "label": "World-writable/Suspicious Files",
        "status": "ALERT" if suspicious else "OK",
        "info": suspicious if suspicious else ["None found"],
        "tip": tip
    } 