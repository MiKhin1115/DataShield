import subprocess
import logging

def block_ip_firewall(ip_address: str) -> bool:
    rule_name = f"DLP_Block_{ip_address}"
    
    # Check if rule exists
    check_cmd = ["powershell", "-Command", f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"]
    try:
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        if rule_name in result.stdout:
            return True
            
        # Add rule
        add_cmd = [
            "powershell", "-Command",
            f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Outbound -RemoteAddress '{ip_address}' -Action Block -ErrorAction Stop"
        ]
        subprocess.run(add_cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to add firewall rule for {ip_address}: {e.stderr if hasattr(e, 'stderr') else e}")
        return False
