🚀 Aliahoran OCServ Auto-Installer & API Agent
 

This Bash script automates the deployment of Cisco AnyConnect (OCServ) VPN server on Linux (Ubuntu/Debian). It is specifically optimized for stability and includes a lightweight PHP API Agent for remote user management.

Designed for high-performance networking with TCP BBR enabled and optimized MTU settings for restricted network environments.

✨ Features
Automated Installation: Installs OCServ, Apache2, PHP, and required dependencies in one go.
Built-in API Agent: Deploys a JSON-based PHP API on port 8080 for remote management (Create/Delete users, Check Online status, Change Password).
Security First: Generates a Random Secure Token for API authentication upon installation.
Network Optimization:
Enables TCP BBR congestion control for better speed.
Optimizes MTU (1200) for stable tunneling.
Configures Firewall (UFW) to allow VPN and API ports.
DTLS/UDP Support: Configured for maximum compatibility (can be toggled in config).
🛠 Prerequisites
OS: Ubuntu 20.04 LTS or 22.04 LTS (Recommended).
Access: Root privileges (sudo or root user).
Ports: Ensure ports 443 (TCP/UDP) and 8080 (TCP) are open on your server provider’s firewall.
📥 Installation
Run the following command in your server terminal. This is a one-click installation script:


content_copy
bash
bash <(curl -Ls https://raw.githubusercontent.com/aliahoran2/install.sh/main/install.sh)
⏳ What happens next?
The system updates and installs dependencies.
OCServ is installed and configured.
Apache and the API Agent are set up on port 8080.
BBR is enabled.
Important: At the end of the installation, the script will display your Server IP, Port, and API Token.
⚠️ SAVE THE API TOKEN! You will need it to connect your management panel to this server.

🔌 API Documentation
The script installs an API agent at http://YOUR_SERVER_IP:8080/api.php. You can interact with it using simple GET/POST requests.

Authentication: All requests must include the token parameter.

1. Create User
Action: create
Parameters: username, password, token
Example:
http://IP:8080/api.php?action=create&username=user1&password=123456&token=YOUR_TOKEN


content_copy
text

### 2. Delete User
*   **Action:** `delete`
*   **Parameters:** `username`, `token`
*   **Example:**
http://IP:8080/api.php?action=delete&username=user1&token=YOUR_TOKEN


content_copy
text

### 3. Change Password
*   **Action:** `passwd`
*   **Parameters:** `username`, `password`, `token`
*   **Example:**
http://IP:8080/api.php?action=passwd&username=user1&password=newpass&token=YOUR_TOKEN


content_copy
text

### 4. Online Users
*   **Action:** `online`
*   **Parameters:** `token`
*   **Response:** JSON list of connected users.
http://IP:8080/api.php?action=online&token=YOUR_TOKEN


content_copy
text

---

## ⚙️ Configuration Details

*   **OCServ Config:** Located at `/etc/ocserv/ocserv.conf`
*   **API File:** Located at `/var/www/html/api.php`
*   **Apache Port:** Changed to `8080` to avoid conflict with OCServ (which uses 443).

## ⚠️ Disclaimer
This script is provided for educational and server management purposes. The author is not responsible for any misuse.

---
**Developed by Aliahoran**


autorenew

thumb_up

thumb_down
