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
    url(r'^index/$', views.index,name='index'),
    url(r'^special/', views.special,name='special'),
    url(r'^fundoonote/', include('fundoonote.urls')),
    path('fundoonote/', include('django.contrib.auth.urls')),
    path('', TemplateView.as_view(template_name='home.html'), name='home'),
    url(r'^signup/$', views.signup, name='signup'),
    url(r'^login/$', views.user_login, name='login'),
    url(r'^logout/$', views.user_logout, name='logout'),
    url(r'^signup/$', views.signup, name='signup'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate, name='activate'),
    url(r'^oauth/', include('social_django.urls', namespace='social')),  # <--
    url(r'^swagger/', get_swagger_view(title="API Docs"), name="Docs"),
    path('notes/', views.NoteView.as_view(), name='notes'),
    path('notess/<int:id>/', views.NoteDetailView.as_view(), name='notes'),
    path('archieve', views.ArchieveNote.as_view(), name='archieve'),
    path('pin/', views.pinNote.as_view(), name='pin'),
    path('trash/', views.TrashView.as_view(), name='trash'),
    path('label/', views.LabelView.as_view(), name='label'),
    # url(r'^upload/$', views.upload_file, name='upload'),
    path('labels/<int:id>/', views.LabelDetailView.as_view(), name='labels'),
    path('s3upload/', views.awss3, name='s3upload'),
    url('', include(router.urls)),
    path('lab/<int:note_id>/', views.MapLabel.as_view(), name='lab'),



]



