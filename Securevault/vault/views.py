from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import Password
from cryptography.fernet import Fernet
from django.conf import settings
import os
from cryptography.fernet import Fernet as _Fernet
import base64
from accounts.utils import require_recent_mfa

def load_fernet_key():
    def _is_valid(k: bytes) -> bool:
        try:
            # must be 32-byte key encoded urlsafe base64 (len 44)
            if not isinstance(k, (bytes, bytearray)):
                return False
            if len(k) != 44:
                return False
            base64.urlsafe_b64decode(k)
            return True
        except Exception:
            return False

    if settings.FERNET_SECRET_KEY:
        k = settings.FERNET_SECRET_KEY.encode()
        if _is_valid(k):
            return k
    key_path = '.fernet.key'
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            existing = f.read().strip()
        if _is_valid(existing):
            return existing
    # generate and persist a good key
    key = _Fernet.generate_key()
    try:
        with open(key_path, 'wb') as f:
            f.write(key)
    except Exception:
        pass
    return key

@login_required
def password_list(request):
    passwords = Password.objects.filter(user=request.user)
    return render(request, 'vault/password_list.html', {'passwords': passwords})

@login_required
def add_password(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        username = request.POST.get('username')
        password = request.POST.get('password')
        url = request.POST.get('url', '')
        notes = request.POST.get('notes', '')

        key = load_fernet_key()
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode()).decode()

        password_obj = Password.objects.create(
            title=title,
            username=username,
            encrypted_password=encrypted_password,
            url=url,
            notes=notes,
            user=request.user
        )
        return redirect('password_list')

    return render(request, 'vault/add_password.html')

@login_required
@require_recent_mfa
def view_password(request, pk):
    password = get_object_or_404(Password, pk=pk, user=request.user)
    key = load_fernet_key()
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(password.encrypted_password.encode()).decode()
    return render(request, 'vault/view_password.html', {'password': password, 'decrypted_password': decrypted_password})
