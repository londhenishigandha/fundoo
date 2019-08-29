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

    # register
    url(r'^register/$', views.RegisterView.as_view(), name='register'),

    # forget page
    url(r'^forgot/$', views.Forgot.as_view(), name='forgot'),

    # login page
    url(r'^login/$', views.user_login, name='login'),

    # logout page
    url(r'^logout/$', views.user_logout, name='logout'),

    # To activate
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.activate, name='activate'),

    # For social login
    url(r'^oauth/', include('social_django.urls', namespace='social')),

    # Swagger
    url(r'^swagger/', get_swagger_view(title="API Docs"), name="Docs"),

    # get all notes
    path('notes/', views.NoteView.as_view(), name='notes'),
    path('notesview/<int:id>/', views.NoteDetailView.as_view(), name='notesview'),

    # get archive notes
    path('archive/', views.ArchiveGetNotes.as_view(), name='archive'),
    path('archive/<int:id>/', views.ArchieveNote.as_view(), name='archive'),

    # get unarchive notes
    path('unarchive/', views.UnArchiveGetNotes.as_view(), name='unarchive'),
    path('unarchive/<int:id>/', views.UnArchieveNote.as_view(), name='unarchive'),

    # get reminder
    path('reminder/<int:id>/', views.SetReminder.as_view(), name='reminder'),
    path('reminder/', views.ReminderView.as_view(), name='reminder'),

    # get pin notes
    path('pin/<int:id>/', views.pinNote.as_view(), name='pin'),
    path('pin/', views.PinnedNotes.as_view(), name='pin'),
    # path('pin1/', views.PinGetNotes.as_view(), name='pin'),

    # get unpin notes
    path('unpin/<int:id>/', views.UnpinNote.as_view(), name='unpin'),
    path('unpin/', views.UnPinGetNotes.as_view(), name='unpin'),

    # trash notes
    path('trash/', views.TrashView.as_view(), name='trash'),

    # get all labels
    path('label/', views.LabelView.as_view(), name='label'),
    path('labels/<int:id>/', views.LabelDetailView.as_view(), name='labels'),

    # add n delete labels
    path('addlabel/<int:id>/', views.Addlabels.as_view(), name='addlabel'),
    path('deletelabel/<int:id>/', views.DeleteLabel.as_view(), name='deletelabel'),

    # image upload
    path('s3upload/', views.awss3, name='s3upload'),
    path('image_upload/', views.s3_upload, name='image_upload'),

    # collaborator
    path('collaborator/<int:id>/', views.Notecollaborator.as_view(), name='collaborator'),
    # path('deletecollaborator/<int:id>/', views.DeleteCollaborator.as_view(), name='deletecollaborator'),
    path('deletecollab/<int:id>/', views.Collaborator.as_view(), name='deletecollab'),

    # get all user through email id
    path('user_email/', views.getAllUser.as_view(), name='user'),

    path('collaborator1/<int:id>/', views.AddCollab.as_view(), name='collaborator1'),
    url('', include(router.urls)),
]



