# File Security Check - Visual Flow Diagrams

## 1. Main Upload Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                     USER UPLOADS FILE                               │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
                  ┌────────────────────┐
                  │  Read File Content │
                  │   Get File Info    │
                  └────────────┬───────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   FILE SECURITY CHECKER RUNS                         │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ 1. FILE TYPE CHECK                                           │   │
│  │    └─ Verify extension in whitelist (PDF, DOC, TXT, etc.)   │   │
│  │    └─ Result: SAFE / UNSAFE                                │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ 2. FILE SIZE CHECK                                           │   │
│  │    └─ Verify size ≤ 50 MB                                   │   │
│  │    └─ Result: OK / TOO_LARGE                                │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ 3. SENSITIVE DATA SCAN                                       │   │
│  │    └─ Search for: Credit Cards, SSN, Passwords, Emails     │   │
│  │    └─ Result: FOUND (n patterns) / NOT_FOUND               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ 4. MALWARE SCAN (ClamAV)                                     │   │
│  │    └─ Connect to ClamAV daemon                              │   │
│  │    └─ Result: CLEAN / INFECTED / UNAVAILABLE               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ 5. COMPUTE FILE HASH                                         │   │
│  │    └─ Generate SHA256 hash                                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
                     ┌──────────────────────┐
                     │  EVALUATE RESULTS    │
                     └──────────┬───────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
         ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
         │  REJECT      │ │    WARN      │ │   ACCEPT     │
         │              │ │              │ │              │
         │ Errors Found │ │ Warnings     │ │ File Safe    │
         │              │ │ Found        │ │              │
         └────────┬─────┘ └────────┬─────┘ └────────┬─────┘
                  │                │                │
                  ▼                ▼                ▼
           ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
           │ Show Error   │ │ Show Warning │ │  Encrypt     │
           │ Page         │ │ Page with    │ │  File        │
           │              │ │ Confirmation │ │              │
           │ Log to Audit │ │              │ │ AES-256      │
           │ (REJECTED)   │ │ User Decides │ │              │
           └──────────────┘ │              │ └────────┬─────┘
                            │ OK?          │          │
                            │ ╱────────────┘          │
                            │╱                       │
                            ▼                        ▼
                       ┌──────────────┐      ┌──────────────┐
                       │   Encrypt    │      │   SUCCESS    │
                       │   & Store    │      │              │
                       │              │      │ File Stored  │
                       └────────┬─────┘      │ Encrypted    │
                                │           │              │
                                └──────┬────┘              │
                                       ▼                   │
                                ┌──────────────┐           │
                                │ Log Activity │           │
                                │ to Audit Log │           │
                                │ (SUCCESS)    │           │
                                └──────────────┘           │
                                       │                   │
                                       └─────────┬─────────┘
                                                 ▼
                                        ┌──────────────────┐
                                        │ Show Success Page│
                                        │ Redirect to      │
                                        │ File List        │
                                        └──────────────────┘
```

---

## 2. Security Check Details

### File Type Check
```
Input: filename = "document.pdf"
       ▼
Is extension in ALLOWED_EXTENSIONS?
├─ YES (pdf) → SAFE ✅
├─ NO (exe)  → UNSAFE ❌
└─ MISSING   → UNSAFE ❌

ALLOWED_EXTENSIONS = {
    pdf, doc, docx, xls, xlsx, ppt, pptx,
    txt, csv, json, xml,
    jpg, jpeg, png, gif, bmp,
    zip, rar, 7z,
    mp3, wav, flac,
    mp4, avi, mkv
}
```

### Sensitive Data Detection
```
Input: file_content = "Card: 1234-5678-9012-3456"
       ▼
Search for patterns:
├─ Credit Cards     : \b(?:\d{4}[-\s]?){3}\d{4}\b
│                     └─ FOUND: "1234-5678-9012-3456" ⚠️
├─ SSN              : \b\d{3}-\d{2}-\d{4}\b
│                     └─ NOT FOUND
├─ Email            : \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
│                     └─ NOT FOUND
├─ Phone            : \b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b
│                     └─ NOT FOUND
├─ Password/Keys    : (?i)(password|passwd|pwd|secret|key|token|api_key)\s*[:=]\s*[^\s]+
│                     └─ NOT FOUND
└─ Bank Account     : \b(?:account|routing)\s*(?:number|#)?[:=\s]*\d{8,17}\b
                      └─ NOT FOUND

Result: FINDINGS = [
    {
        'type': 'credit_card',
        'description': 'Credit Card Number',
        'example': '1234-5678-9012-****'
    }
]
```

### Malware Scan
```
Input: file_content = binary_data
       ▼
Is ClamAV daemon available?
├─ YES:
│  └─ Send content to ClamD
│     ├─ No signature match  → CLEAN ✅
│     └─ Signature match     → INFECTED ❌
│
└─ NO:
   └─ Log warning → UNAVAILABLE ⚠️ (proceed anyway)
```

---

## 3. Recommendation Decision Tree

```
                    CHECK RESULTS
                         │
                         ▼
              ┌────────────────────────┐
              │ ANY ERRORS?            │
              │ (Type, Size, Malware)  │
              └────────┬───────────────┘
                       │
        ┌──────────────┼──────────────┐
        YES            NO
        │              │
        ▼              ▼
    REJECT      ┌─────────────────┐
    ❌          │ ANY WARNINGS?   │
               │ (Sensitive Data)│
               └────────┬────────┘
                        │
            ┌───────────┼───────────┐
            YES        NO
            │          │
            ▼          ▼
          WARN      ACCEPT
          ⚠️        ✅
    (User Choice)  (Auto Proceed)
         │
    ┌────┴────┐
    │          │
  CONFIRM   CANCEL
    │          │
    ▼          ▼
 ACCEPT    REJECT
   ✅         ❌
```

---

## 4. Audit Logging Flow

```
USER ACTION OCCURS
    ▼
┌─────────────────────────────┐
│ File Upload                 │
│ File Download               │
│ Password View               │
│ Login/Logout                │
│ MFA Verification            │
└────────┬────────────────────┘
         ▼
┌─────────────────────────────┐
│ Get Request Context         │
│ ├─ IP Address               │
│ ├─ User                      │
│ ├─ Timestamp                │
│ └─ Action Details           │
└────────┬────────────────────┘
         ▼
┌─────────────────────────────┐
│ Create AuditLog Entry       │
│                             │
│ {                           │
│   'user': 'john_doe',       │
│   'action': 'FILE_UPLOAD',  │
│   'status': 'SUCCESS',      │
│   'ip_address': '192....',  │
│   'timestamp': '2024-01-15',│
│   'details': {...}          │
│ }                           │
└────────┬────────────────────┘
         ▼
    STORED IN DATABASE
         ▼
    AVAILABLE FOR REVIEW
    ├─ Admin Dashboard
    ├─ User Audit Logs
    ├─ Compliance Reports
    └─ Security Investigation
```

---

## 5. File Storage Architecture

```
┌──────────────────────────────────────────────────┐
│              DATABASE                            │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ FileUpload Table                           │  │
│  ├────────────────────────────────────────────┤  │
│  │ id                                         │  │
│  │ title          : "My Document"             │  │
│  │ filename       : "document.pdf"            │  │
│  │ encrypted_content : (BLOB) [encrypted]     │  │
│  │ sha256         : "abc123def456..."         │  │
│  │ file_type_check: "SAFE"                   │  │
│  │ malware_check  : "CLEAN"                  │  │
│  │ sensitive_data_found: True                │  │
│  │ sensitive_data_details: [...]             │  │
│  │ user_id        : 1                        │  │
│  │ uploaded_at    : 2024-01-15 10:30:00      │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ AuditLog Table                             │  │
│  ├────────────────────────────────────────────┤  │
│  │ id                                         │  │
│  │ user_id        : 1                        │  │
│  │ action         : "FILE_UPLOAD"            │  │
│  │ resource_type  : "FILE"                   │  │
│  │ resource_name  : "document.pdf"           │  │
│  │ status         : "SUCCESS"                │  │
│  │ ip_address     : "192.168.1.100"          │  │
│  │ timestamp      : 2024-01-15 10:30:00      │  │
│  │ details        : {"file_size": 5242880}   │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
└──────────────────────────────────────────────────┘
           │
           │ On Download Request
           ▼
┌──────────────────────────┐
│ RETRIEVE FROM DB         │
│                          │
│ 1. Get encrypted_content │
│ 2. Load Fernet key       │
│ 3. Decrypt content       │
│ 4. Return to user        │
│ 5. Log activity          │
└──────────────────────────┘
```

---

## 6. User Confirmation Flow

```
FILE HAS SENSITIVE DATA DETECTED

    ▼

┌─────────────────────────────────────────────────┐
│          WARNING PAGE SHOWN                      │
│                                                 │
│  ⚠️  Security Warning                          │
│                                                 │
│  The file contains potentially sensitive data  │
│                                                 │
│  Findings:                                      │
│  • Credit Card Number (e.g., 1234-5678-...)   │
│                                                 │
│  [ ] I understand and want to proceed          │
│                                                 │
│  [Upload Anyway] [Cancel]                      │
│                                                 │
└────────┬───────────────────────────────┬────────┘
         │                               │
         ▼                               ▼
    USER CONFIRMS               USER CANCELS
         │                           │
         ▼                           ▼
    ENCRYPT & STORE            REDIRECT TO FORM
    LOG: SUCCESS               LOG: REJECTED
     ✅                            ❌
```

---

## 7. Status Badge Reference

```
File Type Check:
├─ 🟢 SAFE     → Extension is in whitelist
├─ 🔴 UNSAFE   → Extension not allowed
└─ ⚪ SKIPPED   → Check not performed

Malware Check:
├─ 🟢 CLEAN       → No malware detected
├─ 🔴 INFECTED    → Malware detected
├─ ⚪ UNAVAILABLE  → ClamAV not running
└─ 🟡 ERROR       → Scan error occurred

Sensitive Data:
├─ 🔴 FOUND (n)   → n patterns detected
└─ 🟢 NOT FOUND   → No patterns detected

Overall Status:
├─ 🟢 ✓ SAFE      → All checks passed
└─ 🔴 ⚠ MALICIOUS → File rejected
```

---

## 8. Audit Log Timeline Example

```
User: john_doe | IP: 192.168.1.100

2024-01-15 09:00:00  LOGIN              ACCOUNT    ✓ SUCCESS
                     └─ User logged in successfully

2024-01-15 09:05:30  FILE_UPLOAD        FILE       ✓ SUCCESS
                     └─ document.pdf (2.5 MB)
                     └─ File type: SAFE
                     └─ Malware: CLEAN
                     └─ Sensitive data: Found 1 pattern

2024-01-15 09:06:00  PASSWORD_CREATE    PASSWORD   ✓ SUCCESS
                     └─ "Banking Password" created

2024-01-15 09:10:15  FILE_DOWNLOAD      FILE       ✓ SUCCESS
                     └─ document.pdf downloaded
                     └─ MFA verified

2024-01-15 09:15:45  FILE_UPLOAD_REJECTED FILE    ✗ FAILURE
                     └─ malware.exe
                     └─ Reason: File type not allowed

2024-01-15 09:20:00  LOGOUT             ACCOUNT    ✓ SUCCESS
                     └─ User logged out
```

---

## 9. Configuration Areas

```
files/security.py
├─ ALLOWED_EXTENSIONS (Line ~15)
│  └─ Whitelist of safe file types
│
├─ SENSITIVE_PATTERNS (Line ~30)
│  └─ Regex patterns for sensitive data
│  ├─ credit_card
│  ├─ ssn
│  ├─ email
│  ├─ phone
│  ├─ password_patterns
│  └─ bank_account
│
└─ check_file_size() (Line ~150)
   └─ max_size_mb parameter (default 50)
```

---

## 10. Component Dependencies

```
┌────────────────────────────────────────────────┐
│             VIEWS LAYER                        │
│  (files/views.py)                              │
│                                                │
│  upload_file()    ──┐                          │
│  download_file()  ──┼─→ Uses FileSecurityChecker
│  audit_logs()     ──┘                          │
└────────────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  Security    │ │    Models    │ │   Audit      │
│  Checker     │ │              │ │   Utils      │
│              │ │  FileUpload  │ │              │
│ scan_type()  │ │  AuditLog    │ │ log_activity()
│ scan_malware()│ │              │ │              │
│ scan_data()  │ │              │ │              │
└──────────────┘ └──────────────┘ └──────────────┘
        │              │              │
        ▼              ▼              ▼
┌────────────────────────────────────────────────┐
│      DATABASE (files/migrations/)              │
│                                                │
│  FileUpload   ← security check results        │
│  AuditLog     ← activity logs                 │
└────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────┐
│      TEMPLATES LAYER                           │
│                                                │
│  upload.html       → Display upload form       │
│  file_list.html    → Show security status     │
│  audit_logs.html   → Display activity history │
└────────────────────────────────────────────────┘
```

---

## 11. Error Handling Flow

```
Exception Occurs During Upload
    ▼
┌──────────────────────────┐
│ Catch Exception          │
└──────┬───────────────────┘
       ▼
┌──────────────────────────────────────────┐
│ Determine Error Type                     │
├──────────────────────────────────────────┤
│ ├─ File type rejected?                  │
│ │  └─ Show specific error               │
│ ├─ File too large?                      │
│ │  └─ Show size limit                   │
│ ├─ Malware detected?                    │
│ │  └─ Show rejection message            │
│ ├─ Encryption error?                    │
│ │  └─ Show error details                │
│ └─ Other error?                         │
│    └─ Show generic message              │
└──────┬───────────────────────────────────┘
       ▼
┌──────────────────────────┐
│ Log to Audit (FAILURE)   │
└──────┬───────────────────┘
       ▼
┌──────────────────────────┐
│ Show Error Page          │
│ with explanation         │
│ and next steps           │
└──────────────────────────┘
```

---

## 12. Integration Points

```
Securevault Application
│
├─ vault/           (Password Management)
│  └─ Password audit logs integrated
│
├─ files/           (File Management) ← YOU ARE HERE
│  ├─ security.py         NEW: Core security logic
│  ├─ audit_utils.py      NEW: Logging functions
│  ├─ models.py           UPDATED: New fields
│  ├─ views.py            UPDATED: Security checks
│  ├─ admin.py            UPDATED: Admin interface
│  └─ urls.py             UPDATED: New routes
│
├─ accounts/        (Authentication)
│  └─ MFA integration with file downloads
│
└─ securevault360/  (Settings)
   └─ No changes needed
```

---

These diagrams provide a comprehensive visual understanding of:
- ✅ How files flow through security checks
- ✅ Decision-making at each stage
- ✅ Database structure and storage
- ✅ Audit logging pipeline
- ✅ User interaction points
- ✅ Component relationships
- ✅ Error handling
- ✅ Integration with existing system

Use these diagrams to understand the system, train others, and plan future enhancements!