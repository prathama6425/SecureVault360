from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
import json

class FileUpload(models.Model):
    title = models.CharField(max_length=200)
    filename = models.CharField(max_length=255, null=True, blank=True)
    encrypted_content = models.BinaryField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, null=True, blank=True)
    is_malicious = models.BooleanField(default=False)
    scan_message = models.TextField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    uploaded_at = models.DateTimeField(default=timezone.now)
    
    # New security fields
    file_type_check = models.CharField(
        max_length=20,
        choices=[('SAFE', 'Safe'), ('UNSAFE', 'Unsafe'), ('SKIPPED', 'Skipped')],
        default='SKIPPED'
    )
    malware_check = models.CharField(
        max_length=20,
        choices=[('CLEAN', 'Clean'), ('INFECTED', 'Infected'), ('UNAVAILABLE', 'Unavailable'), ('ERROR', 'Error')],
        default='UNAVAILABLE'
    )
    sensitive_data_found = models.BooleanField(default=False)
    sensitive_data_details = models.JSONField(default=list, null=True, blank=True)
    is_encrypted = models.BooleanField(default=True)  # Track if content is encrypted
    encryption_key = models.BinaryField(null=True, blank=True)  # Fernet key for encryption
    recovery_key = models.BinaryField(null=True, blank=True)  # Recovery key for backup access

    def __str__(self):
        return self.title


class AuditLog(models.Model):
    """Audit log for tracking all user activities"""
    
    ACTION_CHOICES = [
        ('FILE_UPLOAD', 'File Upload'),
        ('FILE_UPLOAD_REJECTED', 'File Upload Rejected'),
        ('FILE_DOWNLOAD', 'File Download'),
        ('FILE_DELETE', 'File Delete'),
        ('PASSWORD_CREATE', 'Password Create'),
        ('PASSWORD_VIEW', 'Password View'),
        ('PASSWORD_UPDATE', 'Password Update'),
        ('PASSWORD_DELETE', 'Password Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('MFA_VERIFIED', 'MFA Verified'),
        ('MFA_FAILED', 'MFA Failed'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs')
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    resource_type = models.CharField(
        max_length=20,
        choices=[('FILE', 'File'), ('PASSWORD', 'Password'), ('ACCOUNT', 'Account')],
        null=True,
        blank=True
    )
    resource_id = models.IntegerField(null=True, blank=True)
    resource_name = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=[('SUCCESS', 'Success'), ('FAILURE', 'Failure'), ('WARNING', 'Warning')],
        default='SUCCESS'
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    details = models.JSONField(default=dict, null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
