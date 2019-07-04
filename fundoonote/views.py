import imghdr
import os
from boto3.s3.transfer import S3Transfer
from django.utils.datastructures import MultiValueDictKeyError
#from . s3_upload import S3Upload
from rest_framework.response import Response
import self as self
from .forms import UserForm, UserProfileInfoForm
from django.contrib.auth import logout
from django.http import HttpResponseRedirect, JsonResponse, request
from django.urls import reverse
from django.contrib.auth.decorators import login_required
import jwt
from .service import redis_methods
from rest_framework import generics, viewsets, status, serializers
from .models import Notes
from .serializers import NoteSerializer
from .serializers import LabelSerializer
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
import logging
import boto3
from django.http import HttpResponse
from botocore.exceptions import ClientError
from django.http import HttpResponse
from django.shortcuts import render
from django.contrib.auth import login, authenticate
from .forms import SignupForm
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
# from  . import s3_upload


def index(request):
    return render(request, 'fundoonote/index.html')


@login_required
def special(request):
    return HttpResponse("You are logged in !")


@login_required
def user_logout(request):
    logout(request)
    return HttpResponseRedirect(reverse('index'))


def register(request):
    registered = False
    if request.method == 'POST':
        user_form = UserForm(data=request.POST)
        profile_form = UserProfileInfoForm(data=request.POST)
        # Save User Form to Database
        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save()
            # Hash the password
            user.set_password(user.password)
            # Update with Hashed password
            user.save()
            profile = profile_form.save(commit=False)
            # Set One to One relationship between
            # UserForm and UserProfileInfoForm
            profile.user = user
            # Check if they provided a profile picture
            if 'profile_pic' in request.FILES:
                print('found it')
                profile.profile_pic = request.FILES['profile_pic']
            # save model
            profile.save()
            registered = True
        else:
            # One of the forms was invalid if this else gets called.
            print(user_form.errors, profile_form.errors)
    else:
        # Was not an HTTP post so we just render the forms as blank.
        user_form = UserForm()
        profile_form = UserProfileInfoForm()
        # This is the render and context dictionary to feed
        # back to the registration.html file page.
    return render(request, 'fundoonote/registration.html',
                           {
                               'user_form': user_form,
                               'profile_form': profile_form,
                               'registered': registered})


@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        # authenticate the user n password
        user = authenticate(username=username, password=password)
        # check if user details is valid or not
        if user:
            if user.is_active:
                payload = {
                    'id': user.id,
                    'email': user.email,
                }
                # it will create a token
                jwt_token = {'token': jwt.encode(payload, "SECRET_KEY")}
                # print the token
                print("token", jwt_token)
                redis_methods.set_token(self, 'token', jwt_token)
                redistoken = redis_methods.get_token(self, 'token')
                print("token in redis", redistoken)
                login(request, user)
                message = "You have successfully login"
                res = message
                result ={
                        'message': res,
                        'username': user.username,
                        'password': user.password,
                        'status_code': 200
                }
                return JsonResponse({'result':result})
                #decode_jwt_token
            else:
                message = "Your account was inactive."
                status_code =400
                return JsonResponse({'message':message, 'status': status_code})

        else:
            print("Someone tried to login and failed.")
            print("They used username: {} and password: {}".format(username, password))
            message = "Invalid login details given"
            status_code = 400
            return JsonResponse({'message':message, 'status': status_code})
    else:
        return render(request, 'fundoonote/login.html', {})

# method for sign up
@csrf_exempt
def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            # after form.save () user is created
            user = form.save(commit=False)
            # user can’t login without email confirmation.
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            message = render_to_string('account_activation_email.html', {
                'user': user, 'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user,),
            })
            # Sending activation link in terminal
            # user.email_user(subject, message)
            mail_subject = 'Activate your blog account.'
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.send()
            return HttpResponse('Please confirm your email address to complete the registration.')
            # return render(request, 'acc_active_sent.html')
        return render(request, 'fundoonote/login.html', {'form': form})
    else:
        form = SignupForm()
    return render(request, 'fundoonote/signup.html', {'form': form})


@csrf_exempt
def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        # check token if it valid then user will active and login
        user.is_active = True
        user.save()
        login(request, user)
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


@login_required
def home(request):
    return render(request, 'fundoonote/home.html')


class NoteView(APIView):

    def get(self, request):
        notes = Notes.objects.all()
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)

    def post(self, request):
        serializer = NoteSerializer(data=request.data)
        try:
            if serializer.is_valid():
                serializer.save()
        except serializers.ValidationError:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.data, status=200)


class NoteDetailView(APIView):

    def get_object(self, id=None):
        try:
            a = Notes.objects.get(id=id)
            return a
        except Notes.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def put(self, request, id=None):
        data = request.data
        instance= self.get_object(id)
        serializer= NoteSerializer(instance, data=data)
        try:
            if serializer.is_valid():
                serializer.save()
        except serializers.ValidationError:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return JsonResponse(serializer.data, status=200)

    def delete(self, request, id):
        try:
            # GET THE OBJECT OF THAT note_od BY PASSING note_id TO THE get_object() FUNCTION
            instance = self.get_object(id)
            # CHECK THE NOTE is_deleted and is_trashed status Of both are True Then Update Both The Values
            print(instance)
            if instance.is_deleted == False:
                # UPDATE THE is_deleted
                instance.is_deleted = True
                # UPDATE THE is_trashed
                instance.is_trash = True
                # SAVE THE RECORD
                instance.save()
            # RETURN THE RESPONSE MESSAGE AND CODE
            return Response({"Message": "Note Deleted Successfully And Added To The Trash."}, status=200)
            # ELSE EXCEPT THE ERROR AND SEND THE RESPONSE WITH ERROR MESSAGE
        except Notes.DoesNotExist as e:
            return Response({"Error": "Note Does Not Exist Or Deleted.."}, status=Response.status_code)


# To Archieve the note
class ArchieveNote(APIView):

    def get_object(self, id=None):
        try:
            return Notes.object.get(id=id)
        except Notes.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def put(self, request, id=None):
            data = request.data
            instance= self.get_object(id)
            serializer= NoteSerializer(instance, data=data)
            notes = Notes.objects.all()
            try:
                if serializer.is_valid():
                    if notes.is_archive == False or None:
                        notes.is_archive = True
                        notes.save()
                    else:
                        return Response("Already archieve")
                    return Response("Archieve is set")
                else:
                     serializer.save()
            except serializers.ValidationError:
                return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                return JsonResponse(serializer.data, status=200)


# To pin
class pinNote(APIView):

    def get_object(self, id=None):
        try:
            return Notes.object.get(id=id)
        except Notes.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def put(self, request, id=None):
        data = request.data
        instance = self.get_object(id)
        serializer = NoteSerializer(instance, data=data)
        notes = Notes.objects.all()
        try:
            if serializer.is_valid():
                if notes.is_pin == False or None:
                    notes.is_pin = True
                    notes.save()
                else:
                    return Response("Already pin")
                return Response("pin is set")
            else:
                serializer.save()
        except serializers.ValidationError:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            return JsonResponse(serializer.data, status=200)


class TrashView(APIView):

    def get_object(self, id=None):
        try:
            return Notes.object.get(id=id)
        except Notes.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, request):
        notes = Notes.objects.all()
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)

    def put(self, request, id=None):
        data = request.data
        instance = self.get_object(id)
        serializer = NoteSerializer(instance, data=data)
        notes = Notes.objects.all()
        try:
            if serializer.is_valid():
                if notes.is_trash == False or None:
                    notes.is_trash = True
                    notes.save()
                else:
                    return Response("trash note")
            else:
                serializer.save()
                return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except serializers.ValidationError:
            return JsonResponse(serializer.data, status=200)


class LabelView(APIView):

    def get(self, request):
        notes = Notes.objects.all()
        serializer = LabelSerializer(notes, many=True).data
        return Response(serializer, status=200)

    def post(self, request):
        serializer = LabelSerializer(data=request.data)
        try:
            if serializer.is_valid():
                serializer.save()
        except serializers.ValidationError:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.data, status=200)


class LabelDetailView(APIView):

    def get_object(self, id=None):
        try:
            a = Notes.objects.get(id=id)
            return a
        except Notes.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def put(self, request, id=None):
        data = request.data
        instance= self.get_object(id)
        serializer= NoteSerializer(instance,data=data)
        try:
            if serializer.is_valid():
                serializer.save()
        except serializers.ValidationError:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return JsonResponse(serializer.data, status=200)

    def delete(self, request, id):
        try:
            # GET THE OBJECT OF THAT note_od BY PASSING note_id TO THE get_object() FUNCTION
            instance = self.get_object(id)
            # CHECK THE NOTE is_deleted and is_trashed status Of both are True Then Update Both The Values
            print(instance)
            if instance.is_deleted == False:
                # UPDATE THE is_deleted
                instance.is_deleted = True
                # UPDATE THE is_trashed
                instance.is_trash = True
                # SAVE THE RECORD
                instance.save()
            # RETURN THE RESPONSE MESSAGE AND CODE
            return Response({"Message": "Note Deleted Successfully And Added To The Trash."}, status=200)
            # ELSE EXCEPT THE ERROR AND SEND THE RESPONSE WITH ERROR MESSAGE
        except Notes.DoesNotExist as e:
            return Response({"Error": "Note Does Not Exist Or Deleted.."}, status=Response.status_code)


# @csrf_exempt
# def upload_file(request, file=None):
#
#         if request.method == 'POST':
#             file= request.FILES.get('image')
#             file_name = 'bird'
#             s3_client = boto3.client('s3')
#             s3_client.upload_fileobj(file, 'fundoo-bucket', file_name)
#             return HttpResponse('Image is uploaded')



@csrf_exempt
def awss3(request):
    """ this method is used to call the uploadto_aws method from s3_transfer  to upload pic in s3 bucket """
    # res={}
    #
    # uploaded_file = request.FILES.get('document')  # GETTING THE FILE FROM LOCAL DISK
    #
    # print("Upload Image", uploaded_file)
    # print(S3Upload.uploadto_aws(request, uploaded_file))  # RETURNING THE FILE FROM LOCAL DISK TO S3 METHOD
    # return HttpResponse("testing")

    try:
        if request.method == 'POST':
            token = redis_methods.get_token(self, 'token')
            print('abc', token)
        local_directory = '/home/admin1/Python/fundoo_project/media/Images'
        transfer = S3Transfer(boto3.client('s3'))
        client = boto3.client('s3')
        bucket = 'fundoo-bucket'
        for root, dirs, files in os.walk(local_directory):
            for filename in files:
                local_path = os.path.join(root, 'login.jpeg')
                relative_path = os.path.relpath(local_path, local_directory)
                s3_path = os.path.join('s3 path', relative_path)
                if filename.endswith('.pdf'):
                    transfer.upload_file(local_path, bucket, s3_path, extra_args={'ACL': 'private-read'})
                else:
                    transfer.upload_file(local_path, bucket, s3_path)
        return HttpResponse("Image is Upload")

    except Exception as e:
        print(e)

