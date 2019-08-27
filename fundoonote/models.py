from django.db import models
from django.db import models
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser)
from django.conf import settings


# Create your models here.
class AccountManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            raise ValueError('Users must have an email address')

        # if not password:
        #     raise ValueError('Users must have an password')

        user_obj = self.model(
            email=self.normalize_email(email),
        )

        user_obj.set_password(password)
        user_obj.save(using=self._db)
        return user_obj

    def create_staffuser(self, email, username, password):
        user_obj = self.create_user(
            email,
            username,
            password=password,

        )
        user_obj.is_staff = True
        user_obj.save(using=self._db)
        return user_obj

    def create_superuser(self, email, password):
        user_obj = self.create_user(
            email,
            # username,

        )
        user_obj.set_password(password)
        user_obj.is_staff = True
        user_obj.admin = True
        user_obj.save(using=self._db)
        return user_obj


class Account(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    username = models.CharField(max_length=250)
    firstname = models.CharField(max_length=200)
    lastname = models.CharField(max_length=200)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = AccountManager()

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True


# User profile form
class UserProfileInfo(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    portfolio_site = models.URLField(blank=True)
    profile_pic = models.ImageField(upload_to='profile_pics', blank=True)

    def __str__(self):
        return self.user.username


class Labels(models.Model):
    label = models.TextField(max_length=100, unique=True)
    is_deleted = models.BooleanField(default=False)
    # note = models.ManyToManyField(Notess, blank=True)


class Notess(models.Model):
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=1, related_name='owner')
    label = models.ManyToManyField(Labels, related_name='note_labels', blank=True)
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
    reminder = models.DateTimeField(default=None, blank=True, null=True)
    collaborate = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='collaborate_user', blank=True)

    class Meta:
        ordering = ('title',)

    def __str__(self):
        return self.title


class Mapping(models.Model):
    label_id = models.ForeignKey(Labels, on_delete=models.CASCADE, default=1)
    note_id = models.IntegerField()

    def __str__(self):
        return self.title

