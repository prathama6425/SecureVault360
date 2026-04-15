# File Security Check System - Documentation

## Overview

The File Security Check System is a comprehensive security framework for Securevault that protects users by performing three critical security checks on all uploaded files:

1. **File Type Check** - Validates file extensions against an approved list
2. **Malware Scan** - Detects malicious content using ClamAV
3. **Sensitive Data Scan** - Identifies credit cards, SSNs, passwords, emails, and other sensitive patterns

---

## Architecture

### System Flow

```
User Uploads File
        ↓
File Security Checker Runs
        ├─→ File Type Validation
        ├─→ File Size Check
        ├─→ Sensitive Data Detection
        └─→ Malware Scan (ClamAV)
        ↓
Security Decision
├─→ REJECT (Errors found)
├─→ WARN (Warnings found - needs user confirmation)
└─→ ACCEPT (File is safe)
        ↓
If Safe/Confirmed:
├─→ Encrypt with AES-256
├─→ Store in Database
└─→ Log Activity in Audit Log
```

---

## Components

### 1. File Security Checker (`files/security.py`)

Main module for performing all security checks.

#### Key Features:

**Allowed File Types:**
- Documents: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT, CSV, JSON, XML
- Images: JPG, JPEG, PNG, GIF, BMP
- Archives: ZIP, RAR, 7Z
- Media: MP3, WAV, FLAC, MP4, AVI, MKV

**Maximum File Size:** 50 MB (configurable)

**Sensitive Data Patterns Detected:**
- Credit Card Numbers (e.g., 1234-5678-9012-3456)
- Social Security Numbers (e.g., 123-45-6789)
- Email Addresses
- Phone Numbers
- Passwords/API Keys (password=, api_key=, etc.)
- Bank Account Numbers

#### Class: `FileSecurityChecker`

```python
checker = FileSecurityChecker(file_object, filename)
results = checker.run_full_check(content)
```

**Methods:**

- `check_file_type()` - Validates file extension
- `check_file_size()` - Ensures file doesn't exceed size limit
- `scan_sensitive_data()` - Searches for sensitive patterns
- `scan_malware()` - Performs ClamAV malware scan
- `compute_file_hash()` - Generates SHA256 hash
- `run_full_check()` - Executes all checks

**Return Format:**

```python
{
    'is_safe': bool,
    'errors': [list of errors],
    'warnings': [list of warnings],
    'scan_results': {
        'file_type': {'status': 'SAFE', 'extension': 'pdf', ...},
        'file_size': {'status': 'SAFE', 'size_mb': '5.2', ...},
        'sensitive_data': {
            'status': 'COMPLETED',
            'findings_count': 3,
            'findings': [
                {
                    'type': 'credit_card',
                    'description': 'Credit Card Number',
                    'example': '1234-5678-9012-****'
                }
            ]
        },
        'malware': {'status': 'CLEAN', 'message': 'No malware detected', ...}
    },
    'file_hash': 'sha256_hash_value',
    'recommendation': 'ACCEPT' | 'WARN' | 'REJECT'
}
```

---

### 2. Audit Logging (`files/models.py`, `files/audit_utils.py`)

Comprehensive activity tracking for compliance and security.

#### AuditLog Model

**Fields:**
- `user` - User who performed the action
- `action` - Type of action (FILE_UPLOAD, FILE_DOWNLOAD, PASSWORD_VIEW, etc.)
- `resource_type` - Type of resource (FILE, PASSWORD, ACCOUNT)
- `resource_id` - ID of the resource
- `resource_name` - Name of the resource
- `status` - Result of action (SUCCESS, FAILURE, WARNING)
- `ip_address` - Client IP address
- `details` - JSON field for additional information
- `timestamp` - When the action occurred

**Example Log Entry:**

```json
{
    "user": "john_doe",
    "action": "FILE_UPLOAD",
    "resource_type": "FILE",
    "resource_name": "important_document.pdf",
    "status": "SUCCESS",
    "ip_address": "192.168.1.100",
    "timestamp": "2024-01-15 10:30:45",
    "details": {
        "filename": "important_document.pdf",
        "file_size": 2500000,
        "scan_results": {
            "file_type": {"status": "SAFE"},
            "malware": {"status": "CLEAN"},
            "sensitive_data": {
                "findings_count": 0,
                "findings": []
            }
        }
    }
}
```

#### Audit Utility Functions (`files/audit_utils.py`)

**Main Functions:**

- `log_activity()` - Generic activity logger
- `log_file_upload()` - Log successful file uploads
- `log_file_upload_rejected()` - Log rejected file uploads
- `log_file_download()` - Log file downloads
- `log_password_action()` - Log password-related activities

**Example Usage:**

```python
from files.audit_utils import log_file_upload

log_file_upload(
    user=request.user,
    filename='document.pdf',
    file_size=5242880,
    status='SUCCESS',
    request=request,
    scan_results=check_results['scan_results'],
    resource_id=file_upload.id
)
```

---

### 3. Enhanced Models (`files/models.py`)

#### FileUpload Model - New Fields

```python
file_type_check = CharField(
    choices=[('SAFE', 'Safe'), ('UNSAFE', 'Unsafe'), ('SKIPPED', 'Skipped')],
    default='SKIPPED'
)

malware_check = CharField(
    choices=[('CLEAN', 'Clean'), ('INFECTED', 'Infected'), ('UNAVAILABLE', 'Unavailable'), ('ERROR', 'Error')],
    default='UNAVAILABLE'
)

sensitive_data_found = BooleanField(default=False)
sensitive_data_details = JSONField(default=list, null=True, blank=True)
```

---

## File Upload Flow

### Step 1: Initial Upload
User selects a file and submits the upload form.

### Step 2: Security Checks
```python
checker = FileSecurityChecker(uploaded_file, filename)
check_results = checker.run_full_check(content)
```

### Step 3: Handle Results

**If REJECT (Errors found):**
- Display error messages to user
- Log rejected upload to audit log
- Don't encrypt or store file

**If WARN (Warnings found):**
- Display warning page showing:
  - Sensitive data patterns found
  - Examples of detected patterns (masked for privacy)
  - Advice on handling sensitive data
- User can:
  - Confirm and proceed with upload
  - Cancel and choose a different file

**If ACCEPT (File is safe):**
- Proceed with encryption
- Store encrypted content
- Save security check results
- Log successful upload

### Step 4: Encryption and Storage

```python
fernet = Fernet(load_fernet_key())
encrypted_content = fernet.encrypt(content)

file_upload = FileUpload.objects.create(
    title=title,
    filename=filename,
    encrypted_content=encrypted_content,
    sha256=check_results['file_hash'],
    file_type_check=check_results['scan_results']['file_type']['status'],
    malware_check=check_results['scan_results']['malware']['status'],
    sensitive_data_found=len(check_results['scan_results']['sensitive_data']['findings']) > 0,
    sensitive_data_details=check_results['scan_results']['sensitive_data']['findings'],
    user=request.user
)
```

---

## User Interfaces

### Upload Page (`templates/files/upload.html`)

**States:**

1. **Normal Upload Form**
   - File selection input
   - Title input
   - Security information panel

2. **Security Warning** (When sensitive data found)
   - List of detected patterns
   - Example matches (masked)
   - Checkbox for user confirmation
   - "Upload Anyway" button

3. **Upload Rejected** (When errors found)
   - List of errors
   - Security check results
   - "Try Again" button

### File List Page (`templates/files/file_list.html`)

**Enhanced Information:**
- File type check status
- Malware scan status
- Sensitive data detection status
- Overall file safety status
- Quick access to audit logs

### Audit Logs Page (`templates/files/audit_logs.html`)

**Features:**
- Activity history with timestamps
- Filter by action type and status
- Sortable columns
- Pagination (50 items per page)
- Expandable detail view
- IP address tracking

**Available Filters:**
- File Upload
- File Download
- Password View/Create/Update/Delete
- Login/Logout
- MFA Verification
- Success/Failure/Warning status

---

## Installation & Setup

### 1. Install Dependencies

```bash
pip install pyclamd>=0.4.0
```

### 2. Install ClamAV (for malware scanning)

**Windows:**
```bash
# Download ClamAV from https://www.clamav.net/downloads
# Or use: choco install clamav (with Chocolatey)
clamd  # Start ClamAV daemon
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install clamav clamav-daemon
sudo systemctl start clamav-daemon
```

**macOS:**
```bash
brew install clamav
# Start ClamAV daemon manually or add to launchd
```

### 3. Run Database Migrations

```bash
python manage.py migrate files
```

### 4. Update URLs

The URLs are already configured in `files/urls.py`:
- `/files/` - File list
- `/files/upload/` - Upload file
- `/files/download/<id>/` - Download file
- `/files/audit-logs/` - View audit logs

---

## Configuration

### Adjust Allowed File Types

Edit `files/security.py`:

```python
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'txt', 'csv', 'json', 'xml',
    'jpg', 'jpeg', 'png', 'gif', 'bmp',
    'zip', 'rar', '7z',
    'mp3', 'wav', 'flac',
    'mp4', 'avi', 'mkv'
    # Add more as needed
}
```

### Adjust Maximum File Size

In `files/security.py`, method `check_file_size()`:

```python
def check_file_size(self, max_size_mb: int = 50) -> bool:
    # Change max_size_mb to desired limit
```

### Add Custom Sensitive Data Patterns

In `files/security.py`:

```python
SENSITIVE_PATTERNS = {
    'your_pattern': {
        'pattern': r'your_regex_pattern',
        'description': 'Description of pattern'
    },
    # ... existing patterns
}
```

---

## Admin Interface

### File Upload Management

Access via Django Admin (`/admin/files/fileupload/`):
- View all uploaded files
- See security check results
- Filter by:
  - File type check status
  - Malware scan status
  - Sensitive data presence
  - Upload date
- Search by:
  - Title
  - Filename
  - Username

### Audit Log Viewing

Access via Django Admin (`/admin/files/auditlog/`):
- View all user activities
- Filter by:
  - Action type
  - Status (Success/Failure/Warning)
  - Resource type
  - Date range
- Search by:
  - Username
  - Resource name
  - Action
- View detailed information including:
  - IP addresses
  - Scan results
  - Error messages

**Note:** Audit logs are read-only for security and compliance.

---

## Security Considerations

### 1. ClamAV Dependency
- Malware scanning requires ClamAV daemon running
- If not available, system logs warning and allows upload
- Regularly update ClamAV virus definitions

### 2. Sensitive Data Detection
- Uses regex patterns for detection
- May have false positives/negatives
- User confirmation required for files with detected patterns
- Examples are masked to protect privacy

### 3. File Encryption
- All files encrypted with AES-256
- Encryption key stored in `.fernet.key`
- Ensure key is backed up securely

### 4. Audit Logging
- All activities logged with IP addresses
- Logs stored in database
- Regularly review logs for suspicious activity
- Consider archiving old logs for compliance

### 5. Access Control
- Only file owner can download their files
- MFA required for file downloads
- Audit logs only show user's own activities

---

## Troubleshooting

### ClamAV Daemon Not Running
**Problem:** "ClamAV daemon not available" message

**Solution:**
```bash
# Linux
sudo systemctl start clamav-daemon

# macOS
brew services start clamav

# Windows
# Start ClamAV from installed location or task scheduler
```

### File Upload Rejected (File Type)
**Problem:** File type is not allowed

**Solution:**
- Add extension to `ALLOWED_EXTENSIONS` in `files/security.py`
- Or convert file to allowed format

### Sensitive Data False Positive
**Problem:** Legitimate file flagged as containing sensitive data

**Solution:**
- User can confirm and proceed despite warning
- Or modify sensitive data patterns in `files/security.py`

### Audit Logs Not Showing
**Problem:** No audit logs visible after file operations

**Solution:**
```bash
# Check if migration was applied
python manage.py showmigrations files

# Manually migrate if needed
python manage.py migrate files
```

---

## API Reference

### Security Checker

```python
from files.security import FileSecurityChecker

# Create checker instance
checker = FileSecurityChecker(file_object, filename)

# Run all checks
results = checker.run_full_check(file_content)

# Access specific check results
file_type_safe = checker.check_file_type()
size_ok = checker.check_file_size(max_size_mb=50)
findings = checker.scan_sensitive_data(content)
is_clean = checker.scan_malware(content)
file_hash = checker.compute_file_hash(content)
```

### Audit Logging

```python
from files.audit_utils import log_activity, log_file_upload

# Generic logging
log_activity(
    user=user,
    action='FILE_UPLOAD',
    resource_type='FILE',
    resource_id=file_id,
    resource_name=filename,
    status='SUCCESS',
    request=request,
    details={'key': 'value'}
)

# File upload logging
log_file_upload(
    user=user,
    filename=filename,
    file_size=file_size,
    status='SUCCESS',
    request=request,
    scan_results=results
)
```

---

## Performance Considerations

### Database Indexes
- Audit logs indexed on (user, timestamp) and (action, timestamp)
- Enables fast filtering and sorting

### File Size Limits
- 50 MB default limit
- Adjust based on storage capacity
- Consider bandwidth when transferring large files

### ClamAV Scanning
- Scans can take time for large files
- Consider async scanning for production
- Update virus definitions regularly

---

## Compliance & Regulations

This system helps meet requirements for:
- **GDPR**: Data protection with encryption and audit logs
- **HIPAA**: Audit trail for healthcare data
- **PCI-DSS**: Malware scanning and file validation
- **SOC 2**: Activity logging and access controls

---

## Future Enhancements

Potential improvements:
1. Async file scanning for better performance
2. Machine learning for advanced threat detection
3. File quarantine system for suspicious files
4. Automated policy enforcement
5. Integration with external security services
6. Real-time alerts for suspicious uploads
7. Encryption key rotation policies
8. Audit log export/archival

---

## Support & Maintenance

For issues or questions:
1. Check the troubleshooting section
2. Review Django logs for error messages
3. Check ClamAV daemon status
4. Review audit logs for activity history
5. Ensure all dependencies are installed and up to date

---

**Last Updated:** January 2024
**Version:** 1.0