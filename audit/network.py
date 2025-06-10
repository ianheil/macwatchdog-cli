import subprocess

def check_network():
    """Return a summary of network interfaces and active connections."""
    try:
        ifconfig = subprocess.run(["ifconfig"], capture_output=True, text=True)
        netstat = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
        interfaces = []
        for line in ifconfig.stdout.splitlines():
            if line and not line.startswith('\t') and not line.startswith(' '):
                interfaces.append(line.split(':')[0])
        connections = [l for l in netstat.stdout.splitlines() if 'ESTABLISHED' in l]
        tip = "Tip: Unexpected network connections may indicate unwanted remote access or malware."
        return {
            "label": "Network Interfaces & Connections",
            "status": "ALERT" if len(connections) > 0 else "OK",
            "info": f"Interfaces: {', '.join(interfaces)} | Active connections: {len(connections)}",
            "tip": tip
        }
    except Exception as e:
        return {"label": "Network Interfaces & Connections", "status": "ERROR", "info": str(e), "tip": ""} 