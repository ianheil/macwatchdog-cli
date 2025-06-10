import subprocess

def check_admin_users():
    """Return a list of admin users/groups, flagging any that are not standard system users."""
    try:
        # Get admin group members
        result = subprocess.run(['dscl', '.', '-read', '/Groups/admin', 'GroupMembership'], capture_output=True, text=True)
        users = result.stdout.strip().split()[1:]
        # Get all users
        all_users = subprocess.run(['dscl', '.', '-list', '/Users'], capture_output=True, text=True).stdout.strip().splitlines()
        # Exclude system users
        system_users = {'root', '_mbsetupuser', 'daemon', 'nobody', 'Guest', 'admin'}
        suspicious = [u for u in users if u not in system_users]
        tip = "Tip: Only trusted users should have admin privileges. Remove any unknown users from the admin group."
        return {
            "label": "Admin Users/Groups",
            "status": "ALERT" if suspicious else "OK",
            "info": suspicious if suspicious else ["No unknown admin users found"],
            "tip": tip
        }
    except Exception as e:
        return {"label": "Admin Users/Groups", "status": "ERROR", "info": [str(e)], "tip": ""} 