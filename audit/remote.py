import subprocess

def check_remote_management():
    try:
        result = subprocess.run(
            ["systemsetup", "-getremotelogin"],
            capture_output=True, text=True
        )
        enabled = "On" in result.stdout
        return {
            "label": "Remote Login (SSH)",
            "status": "ALERT" if enabled else "OK",
            "info": result.stdout.strip()
        }
    except Exception as e:
        return {"label": "Remote Login (SSH)", "status": "ERROR", "info": str(e)} 