from colorama import Fore, Style, init
import json

init(autoreset=True)

# Cyberpunk theme colors
CYBER_PURPLE = '\033[95m'  # Bright magenta
CYBER_NEON_GREEN = '\033[92m'  # Bright green
CYBER_NEON_YELLOW = '\033[93m'  # Bright yellow
CYBER_NEON_CYAN = '\033[96m'  # Bright cyan
CYBER_DIVIDER = CYBER_PURPLE + ("─" * 50) + Style.RESET_ALL


def color_text(text, color):
    # Allow both colorama Fore or raw ANSI color codes
    if color.startswith("\033["):
        return f"{color}{text}{Style.RESET_ALL}"
    return f"{color}{text}{Style.RESET_ALL}"

def print_category(title):
    print(CYBER_DIVIDER)
    print(color_text(f"== {title} ==", CYBER_PURPLE))
    print(CYBER_DIVIDER)

def print_result(label, status, info=""):
    if status == "OK":
        color = CYBER_NEON_GREEN
    elif status == "ALERT":
        color = CYBER_NEON_YELLOW
    elif status == "ERROR":
        color = Fore.RED
    else:
        color = CYBER_NEON_CYAN
    print(f"{color}{label}: {status}{Style.RESET_ALL}")
    bullet = CYBER_NEON_PURPLE = '\033[95m'  # Bright magenta for bullet
    # If info is a list, print each item with a bullet and indent
    if isinstance(info, list):
        for item in info:
            print(f"    {bullet}•{Style.RESET_ALL} {CYBER_NEON_CYAN}{item}{Style.RESET_ALL}")
    elif info:
        # If info looks like a list (comma or | separated), print each on its own line with a bullet and indent
        if (label.lower().startswith("suspicious") or label.lower().startswith("connected usb") or label.lower().startswith("network interfaces")) and ("," in info or "|" in info):
            sep = "|" if "|" in info else ","
            for item in info.split(sep):
                item = item.strip()
                if item:
                    print(f"    {bullet}•{Style.RESET_ALL} {CYBER_NEON_CYAN}{item}{Style.RESET_ALL}")
        else:
            # Always indent info lines for consistency
            for line in info.splitlines():
                print(f"    {CYBER_NEON_CYAN}{line}{Style.RESET_ALL}")

def print_tip(tip):
    print(color_text(f"  {tip}", CYBER_NEON_CYAN))

def export_report(report, filename, as_json=False):
    with open(filename, "w") as f:
        if as_json:
            json.dump(report, f, indent=2)
        else:
            for category, results in report.items():
                f.write(f"== {category} ==\n")
                for item in results:
                    f.write(f"{item['label']}: {item['status']} {item.get('info','')}\n")
                f.write("\n") 