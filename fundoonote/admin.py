from django.contrib import admin
from .models import UserProfileInfo
from .models import Notes

# Register your models here.
admin.site.register(UserProfileInfo)
admin.site.register(Notes)