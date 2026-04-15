from django.contrib import admin
from .models import FileUpload, AuditLog


@admin.register(FileUpload)
class FileUploadAdmin(admin.ModelAdmin):
    list_display = ("title", "filename", "user", "uploaded_at", "file_type_check", "malware_check", "sensitive_data_found")
    list_filter = ("file_type_check", "malware_check", "sensitive_data_found", "uploaded_at")
    search_fields = ("title", "filename", "user__username")
    readonly_fields = ("sha256", "uploaded_at", "file_type_check", "malware_check", "sensitive_data_found", "sensitive_data_details")
    
    fieldsets = (
        ('Basic Info', {
            'fields': ('title', 'filename', 'user', 'uploaded_at')
        }),
        ('Security', {
            'fields': ('sha256', 'is_malicious', 'scan_message', 'file_type_check', 'malware_check', 'sensitive_data_found', 'sensitive_data_details')
        }),
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "resource_type", "status", "timestamp")
    list_filter = ("action", "status", "resource_type", "timestamp")
    search_fields = ("user__username", "resource_name", "action")
    readonly_fields = ("timestamp", "user", "action", "resource_type", "resource_id", "resource_name", "status", "ip_address", "details")
    
    fieldsets = (
        ('Activity', {
            'fields': ('user', 'action', 'timestamp', 'status')
        }),
        ('Resource', {
            'fields': ('resource_type', 'resource_id', 'resource_name')
        }),
        ('Details', {
            'fields': ('ip_address', 'details'),
            'classes': ('collapse',)
        }),
    )
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
