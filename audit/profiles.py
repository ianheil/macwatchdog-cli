import subprocess
import re
import json

def parse_profiles():
    """Parse all configuration profiles, flag MDM and managed/locked profiles."""
    result = subprocess.run(["profiles", "list", "-all"], capture_output=True, text=True)
    profiles = result.stdout.split("\n\n")
    parsed = []
    for profile in profiles:
        if not profile.strip():
            continue
        info = {}
        for line in profile.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
        # Risk flags
        risk = []
        if any(re.search(r'root', v, re.IGNORECASE) for v in info.values()):
            risk.append("Root certificate")
        if any(re.search(r'vpn', v, re.IGNORECASE) for v in info.values()):
            risk.append("VPN")
        if any(re.search(r'payloadtype.*certificate', v, re.IGNORECASE) for v in info.values()):
            risk.append("Certificate payload")
        info['risk'] = risk
        # MDM detection
        mdm = False
        if 'PayloadType' in info and 'mdm' in info['PayloadType'].lower():
            mdm = True
        elif 'profileidentifier' in info and 'mdm' in info['profileidentifier'].lower():
            mdm = True
        info['mdm'] = mdm
        # Removable detection
        removable = True
        if 'PayloadRemovalDisallowed' in info and info['PayloadRemovalDisallowed'].lower() in ('yes', 'true', '1'):
            removable = False
        info['removable'] = removable
        parsed.append(info)
    return parsed

def check_profiles():
    """Return a detailed report of all configuration profiles, flagging risky and MDM/locked ones."""
    try:
        parsed = parse_profiles()
        if not parsed:
            return {
                "label": "Configuration Profiles (All, with Risk Analysis)",
                "status": "OK",
                "info": ["No configuration profiles found."],
                "tip": ""
            }
        flagged = [p for p in parsed if p['risk']]
        tip = "Tip: Remove suspicious profiles in System Preferences > Profiles. Profiles that install root certificates or VPNs can be risky."
        if flagged:
            details = [json.dumps(p, indent=2) for p in flagged]
            return {
                "label": "Configuration Profiles (All, with Risk Analysis)",
                "status": "ALERT",
                "info": details,
                "tip": tip,
                "profiles": parsed
            }
        else:
            return {
                "label": "Configuration Profiles (All, with Risk Analysis)",
                "status": "OK",
                "info": ["No risky configuration profiles found."],
                "tip": tip,
                "profiles": parsed
            }
    except Exception as e:
        return {"label": "Configuration Profiles (All, with Risk Analysis)", "status": "ERROR", "info": [str(e)], "tip": ""}

def remove_profile(identifier):
    """Remove a configuration profile by its identifier using the system 'profiles' tool."""
    try:
        result = subprocess.run(["sudo", "profiles", "remove", "-identifier", identifier], capture_output=True, text=True)
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)

def get_mdm_info():
    """Return the current MDM enrollment status as reported by the system."""
    try:
        result = subprocess.run(["profiles", "status", "-type", "enrollment"], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e) 