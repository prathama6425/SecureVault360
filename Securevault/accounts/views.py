from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.mail import send_mail
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from decouple import config
from .utils import trigger_mfa_challenge, mark_recent_mfa
import pyotp
import secrets


def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'accounts/home.html')


@require_http_methods(["GET", "POST"])
def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        if not username or not email or not password:
            messages.error(request, 'All fields are required.')
        elif User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
        else:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()
            messages.success(request, 'Account created. We sent an OTP to your email to verify your account.')
            return trigger_mfa_challenge(request, user)
    return render(request, 'accounts/register.html')


@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            return trigger_mfa_challenge(request, user)
        messages.error(request, 'Invalid credentials.')
    return render(request, 'accounts/login.html')


@require_http_methods(["GET", "POST"])
def verify_otp_view(request):
    otp_secret = request.session.get('otp_secret')
    otp_user_id = request.session.get('otp_user_id')
    if not otp_secret or not otp_user_id:
        messages.error(request, 'Session expired. Please login again.')
        return redirect('login')

    if request.method == 'POST':
        code = (request.POST.get('otp') or '').strip()
        totp = pyotp.TOTP(otp_secret, interval=300)
        # accept slight time drift
        if totp.verify(code, valid_window=1):
            # Clear session and login
            user = User.objects.get(id=otp_user_id)
            for k in ['otp_secret', 'otp_user_id']:
                if k in request.session:
                    del request.session[k]
            login(request, user)
            mark_recent_mfa(request)
            next_url = request.session.pop('otp_next', None)
            return redirect(next_url or 'dashboard')
        messages.error(request, 'Invalid or expired OTP.')
    dev_otp = request.session.get('otp_last') if settings.DEBUG else None
    return render(request, 'accounts/verify_otp.html', {'dev_otp': dev_otp})


@login_required
def dashboard_view(request):
    # Include audit logs data for the audit tab
    from files.models import AuditLog, FileUpload
    from django.core.paginator import Paginator

    # Get filter parameters
    selected_action = request.GET.get('action', '')
    selected_status = request.GET.get('status', '')
    page = request.GET.get('page', 1)

    # Filter audit logs
    logs = AuditLog.objects.filter(user=request.user).order_by('-timestamp')

    if selected_action:
        logs = logs.filter(action=selected_action)

    if selected_status:
        logs = logs.filter(status=selected_status)

    # Paginate
    paginator = Paginator(logs, 25)  # 25 logs per page
    page_obj = paginator.get_page(page)

    # Get choices for filters
    all_actions = AuditLog.ACTION_CHOICES
    all_statuses = [('SUCCESS', 'Success'), ('FAILURE', 'Failure'), ('WARNING', 'Warning')]

    # Get file statistics for the file tabs
    files = FileUpload.objects.filter(user=request.user)
    encrypted_files = files.filter(is_encrypted=True)
    total_files_count = files.count()
    encrypted_files_count = encrypted_files.count()
    unencrypted_files_count = total_files_count - encrypted_files_count

    context = {
        'page_obj': page_obj,
        'all_actions': all_actions,
        'all_statuses': all_statuses,
        'selected_action': selected_action,
        'selected_status': selected_status,
        'files': files,
        'encrypted_files': encrypted_files,
        'total_files_count': total_files_count,
        'encrypted_files_count': encrypted_files_count,
        'unencrypted_files_count': unencrypted_files_count,
    }

    return render(request, 'accounts/dashboard.html', context)


def logout_view(request):
    logout(request)
    return redirect('home')

# Create your views here.
