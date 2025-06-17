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
        is_builtin = False
        
        for line in result.stdout.splitlines():
            # Skip built-in Apple devices
            if "Built-in" in line:
                is_builtin = True
                continue
            if "Product ID:" in line:
                if current_device and not is_builtin:
                    devices.append(" | ".join(current_device))
                current_device = []
                is_builtin = False
                current_device.append(line.strip())
            elif ("Vendor ID:" in line or "Serial Number:" in line) and not is_builtin:
                current_device.append(line.strip())
        
        if current_device and not is_builtin:
            devices.append(" | ".join(current_device))
            
        # Filter out empty or default serial numbers
        devices = [d for d in devices if not re.search(r'Serial Number: 0+', d)]
        
        tip = "Tip: Unrecognized USB devices can be a risk. Only trusted devices should be connected."
        return {
            "label": "Connected USB Devices",
            "status": "ALERT" if len(devices) > 0 else "OK",
            "info": devices if devices else ["No external USB devices detected."],
            "tip": tip
        }
    except Exception as e:
        return {"label": "Connected USB Devices", "status": "ERROR", "info": [str(e)], "tip": ""} 