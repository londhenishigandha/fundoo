from django.db import models
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


# User profile form
class UserProfileInfo(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    portfolio_site = models.URLField(blank=True)
    profile_pic = models.ImageField(upload_to='profile_pics', blank=True)


def __str__(self):
    return self.user.username


class Notes(models.Model):
    title = models.TextField(null=False, blank=False)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    color = models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to='static', blank=True)
    is_deleted = models.BooleanField(default=False)
    is_archive = models.BooleanField(default=False, blank=True)
    is_pin = models.BooleanField(default=False, blank=True)
    is_trash = models.BooleanField(default=False, blank=True)

    def __str__(self):
        return self.title
