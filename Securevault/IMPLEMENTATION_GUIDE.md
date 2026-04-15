# File Security Check Implementation Guide

## Quick Start

This guide will help you implement and test the new File Security Check system.

---

## 1. Install Dependencies

### Step 1: Update Python packages

```bash
# Activate virtual environment
.venv\Scripts\activate

# Install new dependency
pip install pyclamd>=0.4.0

# Verify installation
pip list | grep pyclamd
```

---

## 2. Set Up ClamAV (Malware Scanning)

### Windows

**Option A: Using Chocolatey**
```bash
choco install clamav
```

**Option B: Manual Installation**
1. Download from https://www.clamav.net/downloads
2. Extract and follow Windows-specific instructions
3. Update virus definitions before using

**Option C: Using WSL (Windows Subsystem for Linux)**
```bash
# If you have WSL2 installed
wsl
sudo apt-get install clamav clamav-daemon
sudo systemctl start clamav-daemon
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get install clamav clamav-daemon
sudo freshclam  # Update virus definitions
sudo systemctl start clamav-daemon
```

### macOS
```bash
brew install clamav
brew services start clamav
```

---

## 3. Database Migration

Apply the new database schema changes:

```bash
# Navigate to project root
cd c:\Users\ketpa\OneDrive\Desktop\Securevault

# Create migration (should already exist)
# python manage.py makemigrations files

# Apply migrations
python manage.py migrate files

# Verify migration
python manage.py showmigrations files
```

Expected output:
```
[X] 0001_initial
[X] 0002_password_delete_passworditem
[X] 0003_remove_fileupload_file_fileupload_encrypted_content_and_more
[X] 0004_fileupload_is_malicious_fileupload_scan_message_and_more
[X] 0005_add_security_checks_and_audit_log  ← New migration
```

---

## 4. Test the Implementation

### Start Development Server

```bash
python manage.py runserver
```

### Test 1: Simple File Upload

1. Login to http://localhost:8000/accounts/login/
2. Navigate to Dashboard → Upload File
3. Upload a safe text file (e.g., notes.txt with basic content)
4. Expected: File uploads successfully with "SAFE" status

### Test 2: Unsupported File Type

1. Try uploading a `.exe` or `.bat` file
2. Expected: Upload rejected with "File type '.exe' is not allowed"

### Test 3: Large File

1. Create a file larger than 50 MB
2. Try uploading it
3. Expected: Upload rejected with size limit message

### Test 4: File with Sensitive Data

1. Create a text file with credit card-like pattern:
   ```
   Payment details:
   Card: 1234-5678-9012-3456
   CVV: 123
   ```
2. Upload the file
3. Expected: Warning page appears with sensitive data detected
4. Click "Upload Anyway" to proceed

### Test 5: Verify Audit Logs

1. After uploading files, navigate to Files → View Audit Logs
2. You should see entries for:
   - FILE_UPLOAD (successful uploads)
   - FILE_UPLOAD_REJECTED (rejected files)
   - FILE_DOWNLOAD (when you download files)
3. Filter by action or status to test filters

---

## 5. Check Admin Interface

### Access Django Admin

```
http://localhost:8000/admin/
```

### View File Upload Records

1. Go to Files → File Uploads
2. You should see:
   - File type check status (SAFE/UNSAFE/SKIPPED)
   - Malware scan status (CLEAN/INFECTED/UNAVAILABLE)
   - Sensitive data found (True/False)
   - Details of detected patterns

### View Audit Logs

1. Go to Files → Audit Logs
2. Filter by:
   - Action (FILE_UPLOAD, FILE_DOWNLOAD, etc.)
   - Status (SUCCESS, FAILURE, WARNING)
3. Click on an entry to see detailed information
4. Note: Audit logs are read-only (for security)

---

## 6. Configuration

### Customize Allowed File Types

Edit `files/security.py`:

```python
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx',  # Keep existing
    'xyz',  # Add your custom extensions
}
```

### Change Max File Size

Edit `files/security.py`, find `check_file_size()` method:

```python
def check_file_size(self, max_size_mb: int = 50) -> bool:  # Change 50 to your desired size
```

### Add Custom Sensitive Data Patterns

Edit `files/security.py`, `SENSITIVE_PATTERNS` dict:

```python
SENSITIVE_PATTERNS = {
    'custom_pattern': {
        'pattern': r'(?i)my_pattern_\d{4}',  # Regex pattern
        'description': 'My Custom Pattern'
    },
    # ... existing patterns
}
```

---

## 7. Troubleshooting

### Issue: "ClamAV daemon not available"

**Problem:** Malware scanning is skipped

**Solution:**
```bash
# Check if ClamAV is running
ps aux | grep clamd  # Linux/macOS
tasklist | find "clamd"  # Windows

# Start ClamAV if not running
# Windows: Run ClamAV application or batch file
# Linux: sudo systemctl start clamav-daemon
# macOS: brew services start clamav

# Update virus definitions
freshclam  # Or clamscan --update
```

### Issue: Migrations fail

**Solution:**
```bash
# Check migration status
python manage.py showmigrations files

# If stuck, check for conflicts
python manage.py makemigrations files --dry-run

# Force re-apply if needed
python manage.py migrate files zero
python manage.py migrate files
```

### Issue: Import errors with pyclamd

**Solution:**
```bash
# Reinstall pyclamd
pip uninstall pyclamd
pip install pyclamd>=0.4.0

# Test import
python -c "import pyclamd; print('OK')"
```

### Issue: File upload form not showing security info

**Solution:**
1. Clear browser cache (Ctrl+F5)
2. Check if templates are being loaded from correct location
3. Verify `templates/files/upload.html` exists and has new content

---

## 8. Project File Structure

```
Securevault/
├── files/
│   ├── migrations/
│   │   ├── __init__.py
│   │   ├── 0001_initial.py
│   │   ├── ...
│   │   └── 0005_add_security_checks_and_audit_log.py  ← NEW
│   ├── admin.py                    ← UPDATED
│   ├── apps.py
│   ├── models.py                   ← UPDATED
│   ├── security.py                 ← NEW
│   ├── audit_utils.py              ← NEW
│   ├── views.py                    ← UPDATED
│   ├── urls.py                     ← UPDATED
│   └── ...
├── templates/
│   └── files/
│       ├── upload.html             ← UPDATED
│       ├── file_list.html          ← UPDATED
│       ├── audit_logs.html         ← NEW
│       └── ...
├── requirements.txt                ← UPDATED
├── FILE_SECURITY_DOCUMENTATION.md  ← NEW
└── IMPLEMENTATION_GUIDE.md         ← NEW (this file)
```

---

## 9. Key Features Summary

| Feature | Status | Location |
|---------|--------|----------|
| File Type Check | ✅ | `files/security.py` |
| Malware Scanning | ✅ | `files/security.py` |
| Sensitive Data Detection | ✅ | `files/security.py` |
| User Confirmation Flow | ✅ | `files/views.py` |
| Audit Logging | ✅ | `files/models.py`, `files/audit_utils.py` |
| Enhanced File List UI | ✅ | `templates/files/file_list.html` |
| Audit Log Viewer | ✅ | `templates/files/audit_logs.html` |
| Admin Interface | ✅ | `files/admin.py` |
| Encryption | ✅ | `files/views.py` |

---

## 10. Testing Checklist

- [ ] All dependencies installed
- [ ] ClamAV daemon running (optional but recommended)
- [ ] Database migration successful
- [ ] Server starts without errors
- [ ] Login works
- [ ] File upload form displays
- [ ] Safe file uploads successfully
- [ ] Unsafe file types rejected
- [ ] Sensitive data warning shows
- [ ] User can confirm and proceed
- [ ] Audit logs display correctly
- [ ] Admin interface shows new fields
- [ ] File download works
- [ ] File list shows security info

---

## 11. Performance Tips

1. **Malware Scanning:** 
   - Runs synchronously - may slow down large files
   - Consider async implementation for production

2. **Audit Logs:**
   - Database indexed for fast queries
   - Consider archiving old logs periodically

3. **Sensitive Data Patterns:**
   - Regex patterns can be slow on large files
   - Consider skipping text decode on binary files

---

## 12. Security Notes

1. **API Key:** Keep `.fernet.key` secure and backed up
2. **ClamAV:** Update virus definitions regularly
3. **Logs:** Monitor audit logs for suspicious activity
4. **MFA:** Required for file downloads (existing feature)
5. **Encryption:** AES-256 ensures file confidentiality

---

## 13. Next Steps

After implementation:

1. **Deploy to Production:**
   - Update production environment variables
   - Run migrations on production database
   - Set up ClamAV on production server
   - Update SSL certificates if needed

2. **Monitor:**
   - Check audit logs regularly
   - Monitor ClamAV daemon
   - Track file upload patterns

3. **Maintain:**
   - Update ClamAV virus definitions weekly
   - Archive old audit logs monthly
   - Review and update allowed file types quarterly

---

## 14. Support Resources

- **Zencoder Documentation:** See `FILE_SECURITY_DOCUMENTATION.md`
- **Django Documentation:** https://docs.djangoproject.com/
- **ClamAV Documentation:** https://www.clamav.net/documentation
- **Pyclamd Repository:** https://github.com/ValentinBresgen/pyclamd

---

## Questions?

For issues or questions:
1. Check the FILE_SECURITY_DOCUMENTATION.md for detailed information
2. Review the troubleshooting section above
3. Check Django/ClamAV logs for error messages
4. Ensure all dependencies are properly installed

---

**Last Updated:** January 2024
**Version:** 1.0