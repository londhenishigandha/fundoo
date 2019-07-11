from django.db import models
from django.contrib.auth.models import User


# User profile form
class UserProfileInfo(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    portfolio_site = models.URLField(blank=True)
    profile_pic = models.ImageField(upload_to='profile_pics', blank=True)


def __str__(self):
    return self.user.username


class Notess(models.Model):
    # user = models.OneToOneField(User, on_delete="models.CASCADE")
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    label = models.CharField(max_length=100)
    title = models.CharField(max_length=100)
    content = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    color = models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to='static', blank=True)
    is_deleted = models.BooleanField(default=False)
    is_archive = models.BooleanField(default=False, blank=True)
    is_pin = models.BooleanField(default=False, blank=True)
    is_trash = models.BooleanField(default=False, blank=True)
    #collaborate = models.ManyToManyField(User)

    class Meta:
        ordering = ('title',)

    def __str__(self):
        return self.title


class Labels(models.Model):
    label = models.TextField(max_length=100, unique=True)
    is_deleted = models.BooleanField(default=False)
    note = models.ManyToManyField(Notess, blank=True)


class Mapping(models.Model):
    label_id = models.ForeignKey(Labels, on_delete=models.CASCADE, default=1)
    note_id = models.IntegerField()


def __str__(self):
    return self.title
