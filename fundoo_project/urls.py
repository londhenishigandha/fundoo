from django.contrib import admin
from django.urls import path
from django.conf.urls import include
from django.conf.urls import url
from rest_framework_swagger.views import get_swagger_view
from django.views.generic.base import TemplateView
from fundoonote import views
from rest_framework import routers

app_name = 'fundoonote'

router = routers.DefaultRouter()
router.register(r'search', views.NotesDocumentViewSet, basename='search')


urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^index/$', views.index, name='index'),
    url(r'^special/', views.special, name='special'),
    url(r'^fundoonote/', include('fundoonote.urls')),
    path('fundoonote/', include('django.contrib.auth.urls')),
    path('', TemplateView.as_view(template_name='home.html'), name='home'),
    url(r'^register/$', views.RegisterView.as_view(), name='register'),
    url(r'^forgot/$', views.Forgot.as_view(), name='forgot'),
    url(r'^login/$', views.user_login, name='login'),
    url(r'^logout/$', views.user_logout, name='logout'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.activate, name='activate'),
    url(r'^oauth/', include('social_django.urls', namespace='social')),  # <--
    url(r'^swagger/', get_swagger_view(title="API Docs"), name="Docs"),
    path('notes/', views.NoteView.as_view(), name='notes'),
        path('notesview/<int:id>/', views.NoteDetailView.as_view(), name='notesview'),
    path('archieve', views.ArchieveNote.as_view(), name='archieve'),
    path('archieve/<int:id>/', views.ArchieveNote.as_view(), name='archieve'),
    path('reminder/<int:id>/', views.SetReminder.as_view(), name='reminder'),
    path('pin/', views.pinNote.as_view(), name='pin'),
    path('trash/', views.TrashView.as_view(), name='trash'),
    path('label/', views.LabelView.as_view(), name='label'),
    path('labels/<int:id>/', views.LabelDetailView.as_view(), name='labels'),
    path('s3upload/', views.awss3, name='s3upload'),
    path('image_upload/', views.s3_upload, name='image_upload'),
    path('collaborator/<int:id>/', views.Notecollaborator.as_view(), name='collaborator'),
    path('user_email/', views.getAllUser.as_view(), name='user'),


    url('', include(router.urls)),
]



