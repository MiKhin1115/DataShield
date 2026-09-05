# 🚀 Antigravity Enterprise DLP - Live Demo Guide

This guide is designed to help you confidently demonstrate your project to your friends or professors. It covers everything from starting the system to triggering both Web and USB security alerts.

---

## 🛠️ Step 1: Start the Security Engines (The Setup)

Before your friends arrive, get your system running! Open **two** separate PowerShell terminals in your project folder (`c:\Users\M S I\Desktop\usb-operation-demo`).

### Terminal 1 (Start the SOC Dashboard):
This starts your central security dashboard.
```powershell
python -m dlp_agent dashboard
```
> **Action:** Open your browser and go to `http://127.0.0.1:8080`. Leave this open on a monitor so your friends can see it later!

### Terminal 2 (Start the USB Monitor):
This starts the background hardware monitor that watches for physical USB drives.
```powershell
python -m dlp_agent usb
```

### Browser Extension Check:
Make sure your Antigravity Enterprise DLP extension is enabled in `chrome://extensions` or `edge://extensions`.

---

## 🌐 Step 2: The Web Exfiltration Demo (Google Drive / Telegram)

**The Scenario:** Tell your friends, *"Imagine I'm a rogue employee trying to leak the company's confidential payroll data to my personal Google Drive."*

1. Open **Google Drive** (`https://drive.google.com`) or **Telegram Web**.
2. Click **"+ New"** -> **"File Upload"** (or the paperclip icon in Telegram).
3. Select a highly sensitive test file from your project (for example, `02_confidential_payroll.csv` or `05_financial_report.txt`).
4. **The Result:** 
   - A bright warning dialog will instantly pop up: *"Upload of sensitive file blocked automatically by Enterprise Policy!"*
   - Google Drive will not be allowed to upload the file, and if an "Upload Options" dialog appears, clicking "Upload" will immediately fail.

---

## 🔌 Step 3: The Hardware Exfiltration Demo (USB Drive)

**The Scenario:** Tell your friends, *"Okay, so the web is locked down. What if I try to be sneaky and copy the data to a physical USB thumb drive?"*

1. Plug a **USB Flash Drive** into your computer.
2. Open Windows File Explorer and navigate to your project's `data` folder or wherever your test files are.
3. Try to **Copy and Paste** the `02_confidential_payroll.csv` file into the USB Drive folder.
4. **The Result:** 
   - Your USB Monitor terminal will instantly light up red, detecting the file transfer!
   - The deep content inspection engine will scan the file in memory, realize it contains payroll data, and **block the copy operation** from succeeding!

---

## 🚨 Step 4: The Grand Reveal (SOC Dashboard)

**The Scenario:** Tell your friends, *"As a Security Analyst, I can see all of these blocked attacks happening in real-time."*

1. Switch to your browser tab with the **SOC Dashboard** (`http://127.0.0.1:8080`).
2. Refresh the page.
3. **The Result:**
   - Your friends will see exactly **what** you tried to upload, **where** you tried to upload it (e.g., `Google Drive` or `USB Drive`), and **why** it was blocked (e.g., 12 Findings, Critical Risk, External Classification).
   - Show them how you can click the filters, export the incidents, or assign an analyst!

---

### 🎉 Tips for a Great Demo:
- Keep the `02_confidential_payroll.csv` file open on your screen briefly before the demo so your friends can see that it actually contains fake salary and bank account numbers!
- Practice the demo once by yourself before showing them to ensure both terminals are running smoothly.
