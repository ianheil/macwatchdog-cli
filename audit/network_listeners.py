import subprocess
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

def get_project_root():
    """Get the project root directory."""
    return Path(__file__).parent.parent

def get_quarantine_dir():
    """Get or create the quarantine directory for backups."""
    # Use project directory for all quarantined items
    quarantine_dir = get_project_root() / "quarantine" / "ports"
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        return quarantine_dir
    except Exception as e:
        print(f"Error creating quarantine directory: {e}")
        return None

def cleanup_old_backups():
    """Clean up old backup folders and standardize the backup structure."""
    try:
        # Clean up old backup folders in the project's quarantine directory
        project_quarantine = get_project_root() / "quarantine"
        if project_quarantine.exists():
            # Keep the ports directory but clean up old backup folders
            for item in project_quarantine.iterdir():
                if item.is_dir() and item.name.startswith("backup_"):
                    shutil.rmtree(item)
                    print(f"Cleaned up old backup folder: {item}")

        # Clean up any old backups in user's home directory
        user_quarantine = Path.home() / ".macwatchdog" / "quarantine"
        if user_quarantine.exists():
            shutil.rmtree(user_quarantine)
            print(f"Cleaned up old user quarantine directory: {user_quarantine}")
    except Exception as e:
        print(f"Error during cleanup: {e}")

def backup_port_state():
    """Create a backup of current port state."""
    try:
        # Get current port state
        result = check_network_listeners()
        listeners = result.get("listeners", [])
        
        if not listeners:
            return False, "No open ports to backup"
            
        # Create backup with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = get_quarantine_dir() / f"ports_backup_{timestamp}.json"
        
        # Save the port state
        with open(backup_file, 'w') as f:
            json.dump(listeners, f, indent=2)
            
        return True, f"Successfully backed up port state to {backup_file} (Note: This is a record of port state only, not a process restore point)"
    except Exception as e:
        return False, str(e)

def check_network_listeners():
    """Return a list of processes listening on network ports."""
    try:
        result = subprocess.run(['lsof', '-i', '-n', '-P'], capture_output=True, text=True)
        listeners = []
        
        for line in result.stdout.splitlines():
            if 'LISTEN' in line:
                parts = line.split()
                if len(parts) > 8:
                    listeners.append({
                        'process': parts[0],
                        'port': parts[8],
                        'pid': parts[1] if len(parts) > 1 else None
                    })
        
        formatted_listeners = [f"{l['process']} {l['port']}" for l in listeners]
        tip = "Tip: Unexpected open ports may indicate unwanted services or malware. Use 'macwatchdog backup-ports' to create a backup before making changes."
        return {
            "label": "Network Listeners (Open Ports)",
            "status": "ALERT" if listeners else "OK",
            "info": formatted_listeners if listeners else ["No open listeners found"],
            "tip": tip,
            "listeners": listeners  # Include full listener data for management
        }
    except Exception as e:
        return {"label": "Network Listeners (Open Ports)", "status": "ERROR", "info": [str(e)], "tip": ""}

def close_port_process(port):
    """Close a port by killing the process using it."""
    try:
        # Get process info
        result = subprocess.run(['lsof', '-i', f':{port}'], capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"No process found using port {port}"
            
        # Parse output to get PID
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:  # Header + at least one process
            return False, f"No process found using port {port}"
            
        # Get PID from second line (first line is header)
        pid = lines[1].split()[1]
        
        # Create backup before closing
        success, backup_path = backup_port_state()
        if not success:
            return False, f"Failed to create backup: {backup_path}"
            
        # Kill the process
        subprocess.run(['kill', pid], capture_output=True)
        
        return True, f"Successfully closed port {port} (killed process {pid}) (Backup: {backup_path})"
    except Exception as e:
        return False, str(e)

def restore_port_state(backup_file):
    """Restore port state from a backup file."""
    try:
        with open(backup_file, 'r') as f:
            backup = json.load(f)
            
        success_count = 0
        fail_count = 0
        messages = []
        
        for item in backup:
            process = item['process']
            port = item['port'].split(':')[-1]  # Extract just the port number
            
            try:
                if process.lower() == 'python':
                    # For Python processes, try to restart the server
                    try:
                        # Try to start a Python HTTP server on the same port
                        subprocess.Popen(['python3', '-m', 'http.server', port], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE)
                        success_count += 1
                        messages.append(f"Restarted Python HTTP server on port {port}")
                    except Exception as e:
                        fail_count += 1
                        messages.append(f"Failed to restart Python server on port {port}: {str(e)}")
                    continue
                    
                elif process.lower() == 'node':
                    # For Node.js processes, we need the original command
                    # For now, just note that we can't restore without the command
                    messages.append(f"Note: Cannot restore Node.js process on port {port} without original command")
                    continue
                    
                else:
                    # For other processes, try to restart them
                    try:
                        # Try to find the process binary
                        result = subprocess.run(['which', process], capture_output=True, text=True)
                        if result.returncode == 0:
                            binary = result.stdout.strip()
                            # Start the process
                            subprocess.Popen([binary], 
                                          stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE)
                            success_count += 1
                            messages.append(f"Restarted {process} on port {port}")
                        else:
                            fail_count += 1
                            messages.append(f"Could not find binary for {process}")
                    except Exception as e:
                        fail_count += 1
                        messages.append(f"Failed to restart {process} on port {port}: {str(e)}")
                    continue
                
            except Exception as e:
                fail_count += 1
                messages.append(f"Failed to restart {process} on port {port}: {str(e)}")
                continue
                
        if fail_count == len(backup):
            return False, "\n".join(messages)
        else:
            return True, f"Restored {success_count} processes, {fail_count} failed:\n" + "\n".join(messages)
            
    except Exception as e:
        return False, str(e) 