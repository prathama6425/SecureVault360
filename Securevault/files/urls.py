from django.urls import path
from . import views

urlpatterns = [
    path('', views.file_list, name='file_list'),
    path('main/', views.files_main, name='files_main'),
    path('encrypt/', views.encrypt_file_tab, name='encrypt_file_tab'),
    path('encrypt-action/<int:pk>/', views.encrypt_file_action, name='encrypt_file_action'),
    path('keys/', views.key_management, name='key_management'),
    path('recovery/', views.recovery_keys, name='recovery_keys'),
    path('upload/', views.upload_file, name='upload_file'),
    path('upload-simple/', views.upload_simple, name='upload_simple'),
    path('download/<int:pk>/', views.download_file, name='download_file'),
    path('get-key/<int:pk>/', views.get_decryption_key, name='get_decryption_key'),
    path('audit-logs/', views.audit_logs, name='audit_logs'),
    path('code-scan/', views.code_security_scan, name='code_security_scan'),
]
