import os
import subprocess

def is_world_writable(path):
    """Return True if the file is world-writable."""
    return os.access(path, os.W_OK) and oct(os.stat(path).st_mode)[-1] in ['2', '6', '7']

def is_unsigned(path):
    """Return True if the file is not code-signed."""
    try:
        result = subprocess.run(["codesign", "-dv", path], capture_output=True, text=True)
        return "code object is not signed" in result.stderr
    except Exception:
        return False

def check_launch_agents():
    """Return a list of suspicious launch agents/daemons based on keywords, permissions, or signature."""
    suspicious = []
    paths = [
        "/Library/LaunchAgents", "/Library/LaunchDaemons",
        os.path.expanduser("~/Library/LaunchAgents")
    ]
    keywords = ["remote", "mdm", "backdoor", "rat", "suspicious", "hack", "keylog", "spy"]
    for path in paths:
        if os.path.exists(path):
            for f in os.listdir(path):
                full_path = os.path.join(path, f)
                lower_f = f.lower()
                if any(k in lower_f for k in keywords):
                    suspicious.append(full_path + " (keyword)")
                elif is_world_writable(full_path):
                    suspicious.append(full_path + " (world-writable)")
                elif is_unsigned(full_path):
                    suspicious.append(full_path + " (unsigned)")
    tip = "Tip: Suspicious or unsigned launch agents/daemons can be used for persistence or remote control. Remove anything you don't recognize."
    return {
        "label": "Suspicious Launch Agents/Daemons",
        "status": "ALERT" if suspicious else "OK",
        "info": ", ".join(suspicious) if suspicious else "None found",
        "tip": tip
    } 