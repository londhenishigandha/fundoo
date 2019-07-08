from django.contrib import admin
from .models import UserProfileInfo
from .models import Notess
from .models import Labels
from .models import Mapping

admin.site.register(UserProfileInfo)
admin.site.register(Notess)
admin.site.register(Labels)
admin.site.register(Mapping)