import os
import tempfile
import uuid
import hashlib
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
from cryptography.fernet import Fernet
from .models import FileUpload, AuditLog
from .security import FileSecurityChecker, encrypt_file, decrypt_file
from .audit_utils import log_file_upload, log_file_upload_rejected, log_file_download
from vault.views import load_fernet_key
from accounts.utils import require_recent_mfa

@login_required
def file_list(request):
    files = FileUpload.objects.filter(user=request.user).order_by('-uploaded_at')
    encrypted_files = files.filter(is_encrypted=True)

    context = {
        'files': files,
        'encrypted_files': encrypted_files,
        'encrypted_files_count': encrypted_files.count(),
        'total_files_count': files.count(),
        'key_rotations': 0,
    }
    return render(request, 'files/file_list.html', context)

@login_required
def files_main(request):
    """Main files page with tabbed interface"""
    files = FileUpload.objects.filter(user=request.user).order_by('-uploaded_at')
    encrypted_files = files.filter(is_encrypted=True)

    context = {
        'files': files,
        'encrypted_files': encrypted_files,
        'encrypted_files_count': encrypted_files.count(),
        'total_files_count': files.count(),
        'key_rotations': 0,  # This would be tracked separately in a real implementation
    }
    return render(request, 'files/files_main.html', context)

@login_required
def encrypt_file_tab(request):
    """Display file encryption management page"""
    files = FileUpload.objects.filter(user=request.user).order_by('-uploaded_at')
    encrypted_files = files.filter(is_encrypted=True)

    context = {
        'files': files,
        'encrypted_files': encrypted_files,
        'encrypted_files_count': encrypted_files.count(),
        'total_files_count': files.count(),
        'unencrypted_files_count': files.count() - encrypted_files.count(),
    }
    return render(request, 'files/encrypt_file_tab.html', context)

@login_required
@require_http_methods(["POST"])
def encrypt_file_action(request, pk):
    """Encrypt an unencrypted file"""
    try:
        file_upload = get_object_or_404(FileUpload, pk=pk, user=request.user)
        
        if file_upload.is_encrypted:
            messages.warning(request, 'This file is already encrypted.')
            return redirect('encrypt_file_tab')
        
        encryption_key = Fernet.generate_key()
        encrypted_content = encrypt_file(file_upload.encrypted_content, encryption_key)
        
        file_upload.encrypted_content = encrypted_content
        file_upload.is_encrypted = True
        file_upload.encryption_key = encryption_key
        file_upload.recovery_key = encryption_key
        file_upload.save()
        
        log_file_download(
            user=request.user,
            filename=file_upload.filename,
            file_id=file_upload.id,
            request=request
        )
        
        messages.success(request, f'File "{file_upload.title}" has been encrypted successfully.')
    except FileUpload.DoesNotExist:
        messages.error(request, 'File not found.')
    except Exception as e:
        messages.error(request, f'Error encrypting file: {str(e)}')
    
    return redirect('encrypt_file_tab')

@login_required
def key_management(request):
    files = FileUpload.objects.filter(user=request.user).order_by('-uploaded_at')
    encrypted_files = files.filter(is_encrypted=True)

    context = {
        'encrypted_files': encrypted_files,
        'encrypted_files_count': encrypted_files.count(),
        'total_files_count': files.count(),
        'key_rotations': 0,  # Placeholder
    }
    return render(request, 'files/key_management_tab.html', context)
    """Handle key management operations"""
    if request.method == 'POST':
        action = request.POST.get('action')
        file_id = request.POST.get('file_id')

        if action == 'rotate_key' and file_id:
            try:
                file_upload = FileUpload.objects.get(id=file_id, user=request.user, is_encrypted=True)
                # In a real implementation, this would re-encrypt the file with a new key
                # For now, just log the action
                log_file_download(
                    user=request.user,
                    filename=file_upload.filename,
                    file_id=file_upload.id,
                    request=request
                )
                messages.success(request, f'Key rotation initiated for "{file_upload.title}". This is a placeholder - full implementation would re-encrypt the file.')
            except FileUpload.DoesNotExist:
                messages.error(request, 'File not found or access denied.')
            except Exception as e:
                messages.error(request, f'Error rotating key: {str(e)}')

        return redirect('dashboard')

    # GET request - return key management data
    encrypted_files = FileUpload.objects.filter(user=request.user, is_encrypted=True).order_by('-uploaded_at')
    return render(request, 'files/key_management_tab.html', {
        'encrypted_files': encrypted_files,
        'encrypted_files_count': encrypted_files.count(),
        'total_files_count': FileUpload.objects.filter(user=request.user).count(),
        'key_rotations': 0,  # This would be tracked in a real implementation
    })

@login_required
@login_required
def recovery_keys(request):
    encrypted_files = FileUpload.objects.filter(user=request.user, is_encrypted=True).order_by('-uploaded_at')
    return render(request, 'files/recovery_key_tab.html', {'encrypted_files': encrypted_files})
    """Handle recovery key access"""
    encrypted_files = FileUpload.objects.filter(user=request.user, is_encrypted=True).order_by('-uploaded_at')
    return render(request, 'files/recovery_key_tab.html', {
        'encrypted_files': encrypted_files,
    })

@login_required
@require_http_methods(["GET", "POST"])
def upload_file(request):
    if request.method == 'POST':
        pending_token = request.POST.get('pending_upload_token')
        pending_uploads = dict(request.session.get('pending_uploads', {}))
        user_confirmed = request.POST.get('confirm_sensitive_data') == 'on'
        title = request.POST.get('title')
        check_results = None
        file_size = None
        filename = None
        content = None
        
        if pending_token:
            pending_data = pending_uploads.get(pending_token)
            if not pending_data:
                messages.error(request, 'Upload session expired. Please try again.')
                return redirect('upload_file')
            title = pending_data.get('title')
            filename = pending_data.get('filename')
            file_size = pending_data.get('file_size')
            temp_path = pending_data.get('path')
            if not temp_path:
                messages.error(request, 'Upload session expired. Please try again.')
                pending_uploads.pop(pending_token, None)
                request.session['pending_uploads'] = pending_uploads
                request.session.modified = True
                return redirect('upload_file')
            try:
                with open(temp_path, 'rb') as tmp_file:
                    content = tmp_file.read()
                reopened_file = SimpleUploadedFile(name=filename, content=content)
                file_size = reopened_file.size
                checker = FileSecurityChecker(reopened_file, filename)
                check_results = checker.run_full_check(content)
            except FileNotFoundError:
                messages.error(request, 'Upload session expired. Please try again.')
                pending_uploads.pop(pending_token, None)
                request.session['pending_uploads'] = pending_uploads
                request.session.modified = True
                return redirect('upload_file')
            finally:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)
            pending_uploads.pop(pending_token, None)
            request.session['pending_uploads'] = pending_uploads
            request.session.modified = True
            user_confirmed = True
            if check_results and check_results.get('recommendation') == 'REJECT':
                for error in check_results.get('errors', []):
                    messages.error(request, error)
                return render(request, 'files/file_list_tab.html', {
                    'title': title,
                    'check_results': check_results,
                    'files': FileUpload.objects.filter(user=request.user).order_by('-uploaded_at'),
                })
        else:
            uploaded_file = request.FILES.get('file')
            if not title or not uploaded_file:
                messages.error(request, 'Title and file are required.')
                return render(request, 'files/file_list_tab.html', {
                    'title': title,
                    'files': FileUpload.objects.filter(user=request.user).order_by('-uploaded_at'),
                })
            content = uploaded_file.read()
            filename = uploaded_file.name
            file_size = uploaded_file.size
            checker = FileSecurityChecker(uploaded_file, filename)
            check_results = checker.run_full_check(content)
            if check_results['recommendation'] == 'REJECT':
                log_file_upload_rejected(
                    user=request.user,
                    filename=filename,
                    file_size=file_size,
                    reason='; '.join(check_results['errors']),
                    request=request,
                    scan_results=check_results['scan_results']
                )
                for error in check_results['errors']:
                    messages.error(request, error)
                return render(request, 'files/file_list_tab.html', {
                    'title': title,
                    'check_results': check_results,
                    'files': FileUpload.objects.filter(user=request.user).order_by('-uploaded_at'),
                })
            if check_results['recommendation'] == 'WARN' and not user_confirmed:
                tmp_dir = getattr(settings, 'FILE_UPLOAD_TEMP_DIR', None) or tempfile.gettempdir()
                os.makedirs(tmp_dir, exist_ok=True)
                with tempfile.NamedTemporaryFile(delete=False, dir=tmp_dir) as tmp_file:
                    tmp_file.write(content)
                    temp_path = tmp_file.name
                token = str(uuid.uuid4())
                pending_uploads[token] = {
                    'path': temp_path,
                    'filename': filename,
                    'title': title,
                    'file_size': file_size,
                }
                request.session['pending_uploads'] = pending_uploads
                request.session.modified = True
                return render(request, 'files/file_list_tab.html', {
                    'title': title,
                    'check_results': check_results,
                    'show_confirmation': True,
                    'pending_upload_token': token,
                    'files': FileUpload.objects.filter(user=request.user).order_by('-uploaded_at'),
                })
        try:
            if check_results is None:
                messages.error(request, 'Unable to process upload. Please try again.')
                return redirect('files_main')

            # Check if user wants to encrypt the file
            should_encrypt = request.POST.get('encrypt_file') == 'on'

            if should_encrypt:
                # Generate unique encryption key for this file
                encryption_key = Fernet.generate_key()
                encrypted_content = encrypt_file(content, encryption_key)
                final_content = encrypted_content
                is_encrypted = True
            else:
                final_content = content
                is_encrypted = False
                encryption_key = None

            file_upload = FileUpload.objects.create(
                title=title,
                filename=filename,
                encrypted_content=final_content,
                sha256=hashlib.sha256(content).hexdigest(),
                is_malicious=check_results['scan_results'].get('malware', {}).get('is_malicious', False),
                scan_message='Security checks completed',
                user=request.user,
                file_type_check=check_results['scan_results'].get('file_type', {}).get('status', 'SKIPPED'),
                malware_check=check_results['scan_results'].get('malware', {}).get('status', 'SKIPPED'),
                sensitive_data_found=len(check_results['scan_results'].get('sensitive_data', {}).get('findings', [])) > 0,
                sensitive_data_details=check_results['scan_results'].get('sensitive_data', {}).get('findings', []),
                is_encrypted=is_encrypted,
                encryption_key=encryption_key,
                recovery_key=encryption_key
            )
            log_file_upload(
                user=request.user,
                filename=filename,
                file_size=file_size,
                status='SUCCESS',
                request=request,
                scan_results=check_results['scan_results'],
                resource_id=file_upload.id
            )
            encryption_status = "and encrypted" if is_encrypted else "without encryption"
            messages.success(
                request,
                f'File "{title}" uploaded successfully {encryption_status}. '
                f'Security checks: {check_results["scan_results"].get("file_type", {}).get("message", "")}. '
                f'{len(check_results["scan_results"].get("sensitive_data", {}).get("findings", []))} '
                f'sensitive data patterns found.'
            )
            return redirect('files_main')
        except Exception as e:
            messages.error(request, f'Error uploading file: {str(e)}')
            if filename and file_size is not None:
                log_file_upload_rejected(
                    user=request.user,
                    filename=filename,
                    file_size=file_size,
                    reason=f'Encryption error: {str(e)}',
                    request=request
                )
            return redirect('files_main')
    return redirect('files_main')

@login_required
def get_decryption_key(request, pk):
    """Return the decryption key for a file"""
    file_upload = get_object_or_404(FileUpload, pk=pk, user=request.user)

    if not file_upload.is_encrypted or not file_upload.encryption_key:
        return JsonResponse({'success': False, 'error': 'File is not encrypted or key not found'})

    # Log key access
    log_file_download(
        user=request.user,
        filename=file_upload.filename,
        file_id=file_upload.id,
        request=request
    )

    return JsonResponse({
        'success': True,
        'key': file_upload.encryption_key.decode('utf-8') if isinstance(file_upload.encryption_key, bytes) else file_upload.encryption_key
    })

@login_required
@require_recent_mfa
def download_file(request, pk):
    file_upload = get_object_or_404(FileUpload, pk=pk, user=request.user)
    
    try:
        if file_upload.is_encrypted:
            # Use the file-specific encryption key
            if file_upload.encryption_key:
                content = decrypt_file(file_upload.encrypted_content, file_upload.encryption_key)
            else:
                # Fallback to the global key for older files
                content = decrypt_file(file_upload.encrypted_content, load_fernet_key())
        else:
            content = file_upload.encrypted_content

        # Log download
        log_file_download(
            user=request.user,
            filename=file_upload.filename,
            file_id=file_upload.id,
            request=request
        )

        response = HttpResponse(content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_upload.filename}"'
        return response
    except Exception as e:
        messages.error(request, f'Error downloading file: {str(e)}')
        return redirect('file_list')


@login_required
def audit_logs(request):
    """Display audit logs for the current user"""
    logs = AuditLog.objects.filter(user=request.user).order_by('-timestamp')
    
    # Apply filters
    action_filter = request.GET.get('action')
    status_filter = request.GET.get('status')
    
    if action_filter:
        logs = logs.filter(action=action_filter)
    
    if status_filter:
        logs = logs.filter(status=status_filter)
    
    # Pagination
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get unique actions and statuses for filter dropdowns
    all_actions = AuditLog.ACTION_CHOICES
    all_statuses = [('SUCCESS', 'Success'), ('FAILURE', 'Failure'), ('WARNING', 'Warning')]
    
    context = {
        'page_obj': page_obj,
        'all_actions': all_actions,
        'all_statuses': all_statuses,
        'selected_action': action_filter,
        'selected_status': status_filter,
    }

    return render(request, 'files/audit_logs.html', context)


@login_required
@require_http_methods(["POST"])
def upload_simple(request):
    """Simple file upload without security checks - returns JSON"""
    try:
        title = request.POST.get('title', '').strip()
        uploaded_file = request.FILES.get('file')
        
        if not title or not uploaded_file:
            return JsonResponse({
                'success': False,
                'message': 'File title and file are required.'
            })
        
        if uploaded_file.size > 50 * 1024 * 1024:
            return JsonResponse({
                'success': False,
                'message': 'File size exceeds 50MB limit.'
            })
        
        content = uploaded_file.read()
        filename = uploaded_file.name
        
        file_upload = FileUpload.objects.create(
            title=title,
            filename=filename,
            encrypted_content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            user=request.user,
            is_encrypted=False,
            is_malicious=False,
            scan_message='File uploaded without security checks'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'File "{title}" uploaded successfully.',
            'file_id': file_upload.id
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error uploading file: {str(e)}'
        })

@login_required
def code_security_scan(request):
    """Handle code security scanning"""
    scan_results = None

    if request.method == 'POST':
        uploaded_file = request.FILES.get('code_file')
        if not uploaded_file:
            messages.error(request, 'Please select a code file to scan.')
            return render(request, 'files/code_security_scan_tab.html')

        # Check file extension
        allowed_extensions = ['.py', '.js', '.java', '.c', '.cpp', '.h', '.php', '.rb', '.go', '.rs']
        file_ext = '.' + uploaded_file.name.rsplit('.', 1)[-1].lower() if '.' in uploaded_file.name else ''

        if file_ext not in allowed_extensions:
            messages.error(request, f'Unsupported file type. Allowed types: {", ".join(allowed_extensions)}')
            return render(request, 'files/code_security_scan_tab.html')

        # Check file size (limit to 1MB for code files)
        if uploaded_file.size > 1024 * 1024:
            messages.error(request, 'File too large. Maximum size is 1MB.')
            return render(request, 'files/code_security_scan_tab.html')

        try:
            # Read file content
            content = uploaded_file.read().decode('utf-8', errors='ignore')

            # Perform security scan
            from .security import CodeSecurityScanner
            scanner = CodeSecurityScanner(content, uploaded_file.name)
            scan_results = scanner.scan()

            messages.success(request, f'Security scan completed for {uploaded_file.name}')

        except Exception as e:
            messages.error(request, f'Error scanning file: {str(e)}')
            return render(request, 'files/code_security_scan_tab.html')

    return render(request, 'files/code_security_scan_tab.html', {
        'scan_results': scan_results
    })
