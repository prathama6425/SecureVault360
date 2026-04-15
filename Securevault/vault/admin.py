from django.contrib import admin
from .models import Password


@admin.register(Password)
class PasswordAdmin(admin.ModelAdmin):
    list_display = ("title", "username", "user", "created_at")
    search_fields = ("title", "username", "user__username")
