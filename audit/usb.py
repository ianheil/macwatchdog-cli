import subprocess
import re

def check_usb():
    """Return a list of connected USB devices with basic details."""
    try:
        result = subprocess.run(
            ["system_profiler", "SPUSBDataType"],
            capture_output=True, text=True
        )
        devices = []
        current_device = []
        for line in result.stdout.splitlines():
            if re.match(r"^\s*Product ID:", line):
                if current_device:
                    devices.append(" | ".join(current_device))
                    current_device = []
                current_device.append(line.strip())
            elif re.match(r"^\s*Vendor ID:", line) or re.match(r"^\s*Serial Number:", line):
                current_device.append(line.strip())
        if current_device:
            devices.append(" | ".join(current_device))
        tip = "Tip: Unrecognized USB devices can be a risk. Only trusted devices should be connected."
        return {
            "label": "Connected USB Devices",
            "status": "ALERT" if len(devices) > 0 else "OK",
            "info": devices if devices else ["No USB devices detected."],
            "tip": tip
        }
    except Exception as e:
        return {"label": "Connected USB Devices", "status": "ERROR", "info": [str(e)], "tip": ""} 