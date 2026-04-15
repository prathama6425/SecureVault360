from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.conf import settings
from django.core.mail import send_mail
import pyotp
import time


MFA_INTERVAL_SECONDS = 300  # 5 minutes


def _send_otp_email(user, otp_code):
    subject = 'Your SecureVault 360 OTP'
    message = f'Your one-time password is: {otp_code}. It expires in 5 minutes.'
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)


def trigger_mfa_challenge(request, user, next_url=None):
    otp_secret = pyotp.random_base32()
    request.session['otp_secret'] = otp_secret
    request.session['otp_user_id'] = user.id
    if next_url:
        request.session['otp_next'] = next_url
    totp = pyotp.TOTP(otp_secret, interval=MFA_INTERVAL_SECONDS)
    otp_code = totp.now()
    _send_otp_email(user, otp_code)
    if settings.DEBUG:
        request.session['otp_last'] = otp_code
    return redirect('verify_otp')


def mark_recent_mfa(request):
    request.session['mfa_verified_at'] = int(time.time())


def has_recent_mfa(request):
    ts = request.session.get('mfa_verified_at')
    if not ts:
        return False
    return int(time.time()) - int(ts) <= MFA_INTERVAL_SECONDS


def require_recent_mfa(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if has_recent_mfa(request):
            return view_func(request, *args, **kwargs)
        user = request.user
        if not user.is_authenticated:
            messages.error(request, 'Please login to continue.')
            return redirect('login')
        next_url = request.get_full_path()
        return trigger_mfa_challenge(request, user, next_url=next_url)
    return _wrapped






