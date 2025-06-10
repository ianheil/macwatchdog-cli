import subprocess

def check_network_listeners():
    """Return a list of processes listening on network ports."""
    try:
        result = subprocess.run(['lsof', '-i', '-n', '-P'], capture_output=True, text=True)
        listeners = set()
        for line in result.stdout.splitlines():
            if 'LISTEN' in line:
                parts = line.split()
                if len(parts) > 8:
                    listeners.add(parts[0] + ' ' + parts[8])
        tip = "Tip: Unexpected open ports may indicate unwanted services or malware. Only allow trusted services to listen for network connections."
        return {
            "label": "Network Listeners (Open Ports)",
            "status": "ALERT" if listeners else "OK",
            "info": sorted(list(listeners)) if listeners else ["No open listeners found"],
            "tip": tip
        }
    except Exception as e:
        return {"label": "Network Listeners (Open Ports)", "status": "ERROR", "info": [str(e)], "tip": ""} 