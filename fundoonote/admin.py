from django.contrib import admin
from .models import UserProfileInfo
from .models import Notes
from .models import Labels
from .models import Account

admin.site.register(UserProfileInfo)
admin.site.register(Notes)
admin.site.register(Labels)
admin.site.register(Account)

