import os
import subprocess
import json
from datetime import datetime
from pathlib import Path

def get_project_root():
    """Get the project root directory."""
    return Path(__file__).parent.parent

def get_quarantine_dir():
    """Get or create the quarantine directory for backups."""
    # Use project directory for all quarantined items
    quarantine_dir = get_project_root() / "quarantine" / "login_items"
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        return quarantine_dir
    except Exception as e:
        print(f"Error creating quarantine directory: {e}")
        return None

def get_login_items():
    """Get a list of login items."""
    try:
        # Get login items using osascript
        result = subprocess.run([
            'osascript', '-e', 'tell application "System Events" to get the name of every login item'
        ], capture_output=True, text=True)
        
        path_result = subprocess.run([
            'osascript', '-e', 'tell application "System Events" to get the path of every login item'
        ], capture_output=True, text=True)
        
        items = [i.strip() for i in result.stdout.strip().split(',') if i.strip()]
        paths = [p.strip() for p in path_result.stdout.strip().split(',') if p.strip()]
        
        login_items = []
        for i, item in enumerate(items):
            path = paths[i] if i < len(paths) else None
            kind = "Application" if path and path.endswith(".app") else "Script"
            login_items.append({
                'name': item,
                'display_name': item,
                'path': path,
                'kind': kind,
                'hidden': False  # We don't track hidden status
            })
        return login_items
    except Exception as e:
        print(f"Error getting login items: {e}")
        return []

def check_login_items():
    """Return a list of login items with detailed information."""
    try:
        items = get_login_items()
        
        # Format items for display
        formatted_items = []
        for item in items:
            formatted = f"{item['name']}"
            if 'path' in item:
                formatted += f" ({item['path']})"
            if 'kind' in item:
                formatted += f" [{item['kind']}]"
            formatted_items.append(formatted)
        
        tip = "Tip: Only trusted apps/scripts should run at login. Use 'macwatchdog remove-login-item <name>' to remove suspicious items."
        return {
            "label": "Login Items",
            "status": "ALERT" if formatted_items else "OK",
            "info": formatted_items if formatted_items else ["No login items found"],
            "tip": tip,
            "items": items  # Include full item data for removal functionality
        }
    except Exception as e:
        return {"label": "Login Items", "status": "ERROR", "info": [str(e)], "tip": ""}

def remove_login_item(name):
    """Remove a login item by name."""
    try:
        # Create backup first
        items = get_login_items()
        item = next((i for i in items if i['name'] == name), None)
        if not item:
            return False, f"Login item not found: {name}"
            
        # Create backup
        quarantine_dir = get_quarantine_dir()
        if not quarantine_dir:
            return False, "Failed to create quarantine directory"
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = quarantine_dir / f"login_item_backup_{timestamp}.json"
        
        with open(backup_file, 'w') as f:
            json.dump(item, f, indent=2)
            
        # Remove the login item
        result = subprocess.run([
            'osascript', '-e', f'tell application "System Events" to delete login item "{name}"'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            return True, f"Successfully removed login item: {name} (Backup: {backup_file})"
        else:
            return False, f"Failed to remove login item: {result.stderr.strip()}"
    except Exception as e:
        return False, str(e)

def restore_login_item(backup_file):
    """Restore a login item from a backup file."""
    try:
        with open(backup_file, 'r') as f:
            item = json.load(f)
            
        # Add the login item back
        result = subprocess.run([
            'osascript', '-e', f'tell application "System Events" to make new login item at end with properties {{path:"{item["path"]}", hidden:false}}'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            return True, f"Successfully restored login item: {item['display_name']}"
        else:
            return False, f"Failed to restore login item: {result.stderr.strip()}"
    except Exception as e:
        return False, str(e) 