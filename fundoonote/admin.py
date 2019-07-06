from django.contrib import admin
from .models import UserProfileInfo
from .models import Notess
from .models import Labels

# Register your models here.
admin.site.register(UserProfileInfo)
admin.site.register(Notess)