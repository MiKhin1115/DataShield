from __future__ import annotations

from pathlib import Path


SYNTHETIC_FILES = {
    "00_public_company_news.txt": """SYNTHETIC TEST DATA - NOT REAL
The office will close at 5 PM on Friday for scheduled maintenance.
The next company town hall is planned for Monday morning.
""",
    "01_internal_employee_directory.csv": """SYNTHETIC TEST DATA - NOT REAL
employee_id,name,department,email,phone
EMP-1001,Aye Chan,Engineering,aye.chan@example.test,+95 9 555 0101
EMP-1002,Mya Win,Finance,mya.win@example.test,+95 9 555 0102
EMP-1003,Lin Htet,Operations,lin.htet@example.test,+95 9 555 0103
""",
    "02_confidential_payroll.csv": """SYNTHETIC TEST DATA - NOT REAL
CONFIDENTIAL PAYROLL
employee_id,name,salary,bank_account
EMP-1001,Aye Chan,2450000,bank account: 1111-2222-3333
EMP-1002,Mya Win,2800000,bank account: 4444-5555-6666
EMP-1003,Lin Htet,2100000,bank account: 7777-8888-9999
""",
    "03_customer_records.txt": """SYNTHETIC TEST DATA - NOT REAL
CONFIDENTIAL CUSTOMER RECORDS
Customer: Test Customer One
Email: customer.one@example.test
Phone: +95 9 555 0201
Passport: MA1234567
Bank account: 1234-5678-9012

Customer: Test Customer Two
Email: customer.two@example.test
Phone: +95 9 555 0202
Passport: MB7654321
Bank account: 9876-5432-1098
""",
    "04_restricted_credentials.env": """SYNTHETIC TEST DATA - DO NOT USE AS REAL CREDENTIALS
RESTRICTED - INTERNAL USE ONLY
password=DemoPassword123456
api_key=demo_test_key_1234567890abcdef
access_token=demo_test_token_abcdef1234567890
""",
    "05_financial_report.txt": """SYNTHETIC TEST DATA - NOT REAL
CONFIDENTIAL FINANCIAL REPORT
Quarterly compensation reserve: 125000000 MMK
Prepared for the Finance department.
""",
}


def generate_synthetic_dataset(output_directory: Path) -> list[Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    for file_name, content in SYNTHETIC_FILES.items():
        path = output_directory / file_name
        path.write_text(content.strip() + "\n", encoding="utf-8")
        created.append(path)
    return created
