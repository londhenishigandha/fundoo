from django.conf.urls import url
from django.urls import include, path
from fundoonote import views
from fundoonote.views import *

app_name = 'fundoonote'

urlpatterns = [
    url(r'^register/$', views.register, name='register'),
    url(r'^user_login/$', views.user_login, name='user_login'),
    url(r'^signup/$', views.signup, name='signup'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate, name='activate'),
    path('archieve/', views.ArchieveNote.as_view(), name='archieve'),
    path('pin/', views.pinNote.as_view(), name='pin'),


]

