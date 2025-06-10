import os
import subprocess

def check_login_items():
    """Return a list of login items (apps/scripts set to run at user login)."""
    try:
        # Use AppleScript to get login items
        result = subprocess.run([
            'osascript', '-e', 'tell application "System Events" to get the name of every login item'
        ], capture_output=True, text=True)
        items = [i.strip() for i in result.stdout.strip().split(',') if i.strip()]
        tip = "Tip: Only trusted apps/scripts should run at login. Remove any unknown login items from System Preferences > Users & Groups."
        return {
            "label": "Login Items",
            "status": "ALERT" if items else "OK",
            "info": items if items else ["No login items found"],
            "tip": tip
        }
    except Exception as e:
        return {"label": "Login Items", "status": "ERROR", "info": [str(e)], "tip": ""} 