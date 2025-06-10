import subprocess
import os

def check_mdm_and_dep():
    try:
        # Use sudo if not already root for more reliable results
        cmd = ["profiles", "status", "-type", "enrollment"]
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout.strip()
        enrolled = "MDM enrollment: Yes" in output
        dep = "Enrolled via DEP: Yes" in output
        info_lines = output.splitlines()
        info = []
        for line in info_lines:
            if "MDM enrollment:" in line or "Enrolled via DEP:" in line:
                info.append(line.strip())
        return {
            "label": "MDM & DEP Enrollment",
            "status": "ALERT" if enrolled else "OK",
            "info": info if info else [output],
            "dep_enrolled": dep,
            "mdm_enrolled": enrolled,
            "tip": "Run as root (sudo) for most accurate results." if os.geteuid() != 0 else ""
        }
    except Exception as e:
        return {"label": "MDM & DEP Enrollment", "status": "ERROR", "info": [str(e)]}

check_mdm = check_mdm_and_dep 