# Generated migration for adding security checks and audit logging

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('files', '0004_fileupload_is_malicious_fileupload_scan_message_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Add security fields to FileUpload
        migrations.AddField(
            model_name='fileupload',
            name='file_type_check',
            field=models.CharField(
                choices=[('SAFE', 'Safe'), ('UNSAFE', 'Unsafe'), ('SKIPPED', 'Skipped')],
                default='SKIPPED',
                max_length=20
            ),
        ),
        migrations.AddField(
            model_name='fileupload',
            name='malware_check',
            field=models.CharField(
                choices=[('CLEAN', 'Clean'), ('INFECTED', 'Infected'), ('UNAVAILABLE', 'Unavailable'), ('ERROR', 'Error')],
                default='UNAVAILABLE',
                max_length=20
            ),
        ),
        migrations.AddField(
            model_name='fileupload',
            name='sensitive_data_found',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='fileupload',
            name='sensitive_data_details',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        # Create AuditLog model
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(
                    choices=[
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
                    ],
                    max_length=30
                )),
                ('resource_type', models.CharField(
                    blank=True,
                    choices=[('FILE', 'File'), ('PASSWORD', 'Password'), ('ACCOUNT', 'Account')],
                    max_length=20,
                    null=True
                )),
                ('resource_id', models.IntegerField(blank=True, null=True)),
                ('resource_name', models.CharField(blank=True, max_length=255, null=True)),
                ('status', models.CharField(
                    choices=[('SUCCESS', 'Success'), ('FAILURE', 'Failure'), ('WARNING', 'Warning')],
                    default='SUCCESS',
                    max_length=20
                )),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('details', models.JSONField(default=dict, null=True, blank=True)),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='audit_logs', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        # Add indexes
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['user', '-timestamp'], name='files_audit_user_time_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['action', '-timestamp'], name='files_audit_action_time_idx'),
        ),
    ]