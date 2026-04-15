"""
Audit logging utilities for tracking user activities
"""
from .models import AuditLog
from django.http import HttpRequest
from typing import Optional, Dict, Any


def get_client_ip(request: HttpRequest) -> str:
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_activity(
    user,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[int] = None,
    resource_name: Optional[str] = None,
    status: str = 'SUCCESS',
    request: Optional[HttpRequest] = None,
    details: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """
    Create an audit log entry for user activity
    
    Args:
        user: Django User object
        action: Action type (e.g., 'FILE_UPLOAD', 'PASSWORD_VIEW')
        resource_type: Type of resource ('FILE', 'PASSWORD', 'ACCOUNT')
        resource_id: ID of the resource
        resource_name: Name of the resource
        status: Status of the action ('SUCCESS', 'FAILURE', 'WARNING')
        request: Django HttpRequest object (optional, to get IP)
        details: Additional details as dictionary
    
    Returns:
        Created AuditLog object
    """
    ip_address = None
    if request:
        ip_address = get_client_ip(request)
    
    if details is None:
        details = {}
    
    audit_log = AuditLog.objects.create(
        user=user,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        status=status,
        ip_address=ip_address,
        details=details
    )
    
    return audit_log


def log_file_upload(
    user,
    filename: str,
    file_size: int,
    status: str = 'SUCCESS',
    request: Optional[HttpRequest] = None,
    scan_results: Optional[Dict] = None,
    errors: Optional[list] = None,
    resource_id: Optional[int] = None
) -> AuditLog:
    """
    Log file upload activity
    """
    details = {
        'filename': filename,
        'file_size': file_size,
        'scan_results': scan_results or {},
        'errors': errors or []
    }
    
    return log_activity(
        user=user,
        action='FILE_UPLOAD',
        resource_type='FILE',
        resource_id=resource_id,
        resource_name=filename,
        status=status,
        request=request,
        details=details
    )


def log_file_upload_rejected(
    user,
    filename: str,
    file_size: int,
    reason: str,
    request: Optional[HttpRequest] = None,
    scan_results: Optional[Dict] = None
) -> AuditLog:
    """
    Log rejected file upload activity
    """
    details = {
        'filename': filename,
        'file_size': file_size,
        'rejection_reason': reason,
        'scan_results': scan_results or {}
    }
    
    return log_activity(
        user=user,
        action='FILE_UPLOAD_REJECTED',
        resource_type='FILE',
        resource_name=filename,
        status='FAILURE',
        request=request,
        details=details
    )


def log_file_download(
    user,
    filename: str,
    file_id: int,
    request: Optional[HttpRequest] = None
) -> AuditLog:
    """
    Log file download activity
    """
    return log_activity(
        user=user,
        action='FILE_DOWNLOAD',
        resource_type='FILE',
        resource_id=file_id,
        resource_name=filename,
        request=request
    )


def log_password_action(
    user,
    action: str,  # PASSWORD_CREATE, PASSWORD_VIEW, PASSWORD_UPDATE, PASSWORD_DELETE
    password_title: str,
    password_id: int,
    request: Optional[HttpRequest] = None,
    details: Optional[Dict] = None
) -> AuditLog:
    """
    Log password-related activities
    """
    return log_activity(
        user=user,
        action=action,
        resource_type='PASSWORD',
        resource_id=password_id,
        resource_name=password_title,
        request=request,
        details=details or {}
    )