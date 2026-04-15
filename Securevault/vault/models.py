from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

class Password(models.Model):
    title = models.CharField(max_length=200)
    username = models.CharField(max_length=100)
    encrypted_password = models.TextField()
    url = models.URLField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='passwords')
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.title
