from django.db import models
from django.contrib.auth import get_user_model


User = get_user_model()


class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="token")
    token = models.CharField(max_length=256, blank=True, null=True)
