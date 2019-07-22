import json
import os
import pickle
import redis
from boto3.s3.transfer import S3Transfer
from django.utils.decorators import method_decorator
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
import self as self
from .decorators import my_login_required
from .documents import NotesDocument
from django.contrib.auth import logout
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.contrib.auth.decorators import login_required
import jwt
from .service import redis_methods
from rest_framework import generics, viewsets, status, serializers
from .models import Notess, Labels
from .serializers import NoteSerializer, NotesDocumentSerializer, RegisterSerializer, LoginSerializer
from .serializers import LabelSerializer
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
import boto3
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth.models import User
from django.core.mail import EmailMessage, send_mail
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response

from django_elasticsearch_dsl_drf.constants import (
    LOOKUP_FILTER_RANGE,
    LOOKUP_QUERY_IN,
    LOOKUP_QUERY_GT,
    LOOKUP_QUERY_GTE,
    LOOKUP_QUERY_LT,
    LOOKUP_QUERY_LTE,
)
from django_elasticsearch_dsl_drf.filter_backends import (
    FilteringFilterBackend,
    OrderingFilterBackend,
    DefaultOrderingFilterBackend,
    CompoundSearchFilterBackend, FunctionalSuggesterFilterBackend)
from django_elasticsearch_dsl_drf.viewsets import DocumentViewSet


def index(request):
    return render(request, 'fundoonote/index.html')


@login_required
def special(request):
    return HttpResponse("You are logged in !")


@login_required
def user_logout(request):
    logout(request)
    redis_methods.flush(self)
    return HttpResponseRedirect(reverse('index'))


@csrf_exempt
def user_login(request):

    # print(request.data)
    request_data=json.loads((request.body).decode('utf-8'))
    # request_data=eval(request_data1)
    # print(request_data1)

    # import ast
    # request_data=ast.literal_eval(request_data1)

    print(type(request_data),'------------>')
    print(request_data)

    if request.method == 'POST':
        # username = request.POST.get('username')
        username = request_data['username']

        print(username, '---------------->')
        # password = request.POST.get('password')
        password = request_data['password']

        print(password, '------------>')

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
                jwt_token = jwt.encode(payload, 'secret', 'HS256').decode('utf-8')
                print("abc", jwt_token)
                redis_methods.set_token(self, 'token', jwt_token)
                restoken = redis_methods.get_token(self, 'token')
                print("token in redis", restoken)
                login(request, user)
                message = "you have successfully logged in"
                res = message
                result = {
                        'message': res,
                        'username': user.username,
                        'password': user.password,
                        # 'status_code': 200,
                        'jwt_token': jwt_token
                }
                return JsonResponse({'result': result})
                #  decode_jwt_token
            else:
                message = "Your account was inactive."
                status_code = 400
                return JsonResponse({'message': message, 'status': status_code})

        else:
            print("Someone tried to login and failed.")
            print("They used username: {} and password: {}".format(username, password))
            message = "Invalid login details given"
            status_code = 400
            return JsonResponse({'message': message, 'status': status_code})
    else:
        return render(request, 'fundoonote/login.html', {})


class RegisterView(APIView):
    serializer_class = RegisterSerializer
    def post(self, request):

        redis = redis_methods()
        serializer = RegisterSerializer(data=request.data)
        print("Serializers", serializer)
        print(serializer.is_valid())
        if serializer.is_valid():
            user = serializer.save()
            if user:
                # get the current site url
                current_site = get_current_site(request)
                # create the email subject
                mail_subject = "Activate Your Account"
                # create the email body with activation link
                message = render_to_string("acc_active_email.html", {
                                            'user': user,  # pass the user
                                            'domain': current_site.domain,  # pass the current domail
                                            'uid': urlsafe_base64_encode(force_bytes(user.pk)),  # pass the uid in byte format
                                            'token': account_activation_token.make_token(user)  # pass the token
                                        })
                to_email = serializer.validated_data.get('email')  # get the user email
                print(to_email)
                email = EmailMessage(mail_subject, message, to=[to_email])
                email.send()  # send the mail for activation account
                # return message
                # return HttpResponse('Please confirm your email address to complete the registration')
                print(serializer.data)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors)


@csrf_exempt
def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        # return redirect('home')
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


class Forgot(APIView):

    def post(self, request):
        email = request.data.get('email')
        print(email)
        domain = "localhost:3000/confirm"
        if email:
            user = User.objects.get(email=email)
            print(user)
            current_site = get_current_site(request)
            mail_subject = "Reset your password"
            # create the email body with activation link
            message = render_to_string("acc_active_email.html", {
                'user': user,  # pass the user
                'domain': current_site.domain,  # pass the current domail
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),  # pass the uid in byte format
                'token': account_activation_token.make_token(user)  # pass the token
                })
            to_email = email
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.send()  # send the mail for activation account
            # return message
            return HttpResponse('Please confirm your email address to complete the registration')
            # return HttpResponse({"asda": "Mail Send Success Check Link"})
        else:
            return HttpResponse({"asda": "Fail"})


@csrf_exempt
def forgot_pass_activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        # return redirect('home')
        return HttpResponse('Thank you for your email confirmation. Now you can reset your password:')
    else:
        return HttpResponse('Activation link is invalid!')


@csrf_exempt
def confirm(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.setpassword = True
        user.save()
        return HttpResponse('Password reset:')


@login_required
def home(request):
    return render(request, 'fundoonote/home.html')


# to create a note
class NoteView(APIView):
    serializer_class = NoteSerializer
    def get(self, request):

        redistoken = redis_methods.get_token(self, 'token')  # gets the token from the redis cache
        print("get the  Token", redistoken)
        # decodes the token
        decoded_token = jwt.decode(redistoken, 'secret', algorithms=['HS256'])
        # decodes the jwt token and gets the value of user details
        user_id = decoded_token.get('id')
        user = User.objects.get(id=user_id)
        notes = Notess.objects.filter(created_by=user)
        serializer = NoteSerializer(notes, many=True).data
        r = redis.StrictRedis('localhost')
        mydict = notes
        p_mydict = pickle.dumps(mydict)
        r.set('mydict', p_mydict)
        read_dict = r.get('mydict')
        yourdict = pickle.loads(read_dict)
        print("Notes in redis cache", yourdict)
        return Response(serializer, status=200)

    def post(self, request):
        result = {"message": "something bad happened",  # give the element in rest api
                  "success": False,
                  "data": {}}
        try:
            data = request.data
            serializer = NoteSerializer(data=data)
            print(serializer)
            print(serializer.is_valid())
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                result["message"] = "Note created successfully "
                result['success'] = True
                result["data"] = serializer.data
                result['mail'] = "mail send successfully"
                notes = json.dump(result)
                for collab_id in serializer.data['collaborate']:
                    user = User.objects.get(id=collab_id)
                    print(collab_id)
                    if user:
                        send_mail('Subject here', notes, request.user.email, [str(user.email)], fail_silently=False)

            return Response(result, status=200)
        except:
            return Response(result, status=400)

    # def post(self, request):
    #     serializer = NoteSerializer(data=request.data)
    #     try:
    #         if serializer.is_valid():
    #             serializer.save()
    #
    #     except serializers.ValidationError:
    #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    #     else:
    #         return Response(serializer.data, status=200)


# to update and delete the note
class NoteDetailView(APIView):

    def get_object(self, id=None):
        try:
            a = Notess.objects.get(id=id)
            return a
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, request,id=None):
        notes = self.get_object(id)
        serializer = NoteSerializer(notes).data
        return Response(serializer)

    def put(self, request, id=None):
        data = request.data
        instance = self.get_object(id)
        serializer = NoteSerializer(instance, data=data)
        try:
            if serializer.is_valid():
                serializer.save()
        except serializers.ValidationError:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return JsonResponse(serializer.data, status=200)

    def delete(self, request, id):
        try:
            # get the object of that note_od by passing note_id to the getobject() FUNCTION
            instance = self.get_object(id)
            # check the note is_deleted and is_trashed status Of both are true then update both the values
            print(instance)
            if instance.is_deleted == False:
                # update the is_deleted
                instance.is_deleted = True
                # update the  is_trashed
                instance.is_trash = True
                # save the record
                instance.save()
            # return the response
            return Response({"Message": "Note Deleted Successfully And Added To The Trash."}, status=200)
        except Notess.DoesNotExist as e:
            return Response({"Error": "Note Does Not Exist Or Deleted.."}, status=Response.status_code)


# To Archieve the note
class ArchieveNote(APIView):
    def get(self, request, is_archive=None):
        notes = Notess.objects.filter(is_archive=True)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)


# To pin
class pinNote(APIView):

    def get_object(self, id=None):
        try:
            return Notess.object.get(id=id)
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def put(self, request, id=None):
        data = request.data
        instance = self.get_object(id)
        serializer = NoteSerializer(instance, data=data)
        notes = Notess.objects.all()
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


# for trash
class TrashView(APIView):
    def get(self, request, is_trash=None):
        notes = Notess.objects.filter(is_trash=True)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)


# to create a label view
class LabelView(APIView):

    def get(self, request):

        label = Labels.objects.all()
        serializer = LabelSerializer(label, many=True).data
        return Response(serializer, status=200)

    def post(self, request):
        print(request.data)
        user = request.user
        print(user)
        serializer = LabelSerializer(data=request.data)
        try:
            if serializer.is_valid():
                serializer.save()
        except serializers.ValidationError:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.data, status=200)


# for update and delete the label
class LabelDetailView(APIView):

    def get_object(self, id=None):
        try:
            a = Labels.objects.get(id=id)
            return a
        except Labels.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, request, id=None):
        label = self.get_object(id)
        serializer = LabelSerializer(label).data
        return Response(serializer)

    def put(self, request, id=None):
        data = request.data
        instance = self.get_object(id)
        serializer = LabelSerializer(instance, data=data)
        try:
            if serializer.is_valid():
                serializer.save()
        except serializers.ValidationError:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return JsonResponse(serializer.data, status=200)


def delete(self, request, id):
    try:
        # get the object of that note_od by passing note_id to the get_object() function
        instance = self.get_object(id)
        # check the node is_deleted and is_trashed status Of both are True Then Update Both The Values
        print(instance)
        if instance.is_deleted == False:
            # update the is_deleted
            instance.is_deleted = True
            # update the is_trashed
            instance.is_trash = True
            # save the record
            instance.save()
        # return the response
        return Response({"Message": "Note Deleted Successfully And Added To The Trash."}, status=200)
    except Notess.DoesNotExist as e:
        return Response({"Error": "Note Does Not Exist Or Deleted.."}, status=Response.status_code)


@csrf_exempt
def awss3(request):

    try:
        if request.method == 'POST':
            local_directory = '/home/bridgeit/PycharmProjects/fundoo_project/media/Images'
            transfer = S3Transfer(boto3.client('s3'))
            client = boto3.client('s3')
            bucket = 'fundoo-bucket'
            # recursively copy files from local directory to boto bucket
            for root, dirs, files in os.walk(local_directory):
                for filename in files:
                    local_path = os.path.join(root, 'sheet.jpg')
                    relative_path = os.path.relpath(local_path, local_directory)
                    s3_path = os.path.join('s3 path1', relative_path)
                    if filename.endswith('.jpeg'):
                        transfer.upload_file(local_path, bucket, s3_path, extra_args={'ACL': 'private-read'})
                    else:
                        transfer.upload_file(local_path, bucket, s3_path)
            return HttpResponse("Image is Upload")

    except Exception as e:
        return e


@csrf_exempt
def s3_upload(request):
    try:
        message = None
        status_code = 500
        if request.method == 'POST':
            # taking input image files
            uploaded_file = request.FILES.get('document')
            if uploaded_file is None:
                message = "Empty file can not be uploaded"
                status_code = 400
                return JsonResponse({'message': message, 'status': status_code})
            else:
                file_name = 'image'
                s3_client = boto3.client('s3')
                s3_client.upload_fileobj(uploaded_file, 'fundoo-bucket', Key=file_name)
                message = "Image successfully uploaded"
                status_code = 200     # success msg
                return JsonResponse({'message': message, 'status': status_code})
        else:
            status_code = 400    # bad request
            message = "The request is not valid."
        return JsonResponse({'message': message, 'status': status_code})
    except RuntimeError:
        print(" ")


# For note document view to search data
class NotesDocumentViewSet(DocumentViewSet):
    document = NotesDocument
    serializer_class = NotesDocumentSerializer
    lookup_field = 'id'
    filter_backends = [
        FilteringFilterBackend,
        OrderingFilterBackend,
        DefaultOrderingFilterBackend,
        CompoundSearchFilterBackend,
        FunctionalSuggesterFilterBackend
    ]

    # search in all fields in one request
    search_fields = (
        'title',
        'content',
        'color',
    )

    # List of filter fields
    filter_fields = {
        'id': {
            'field': 'id',
            'lookups': [
                # to set the extent search,
                LOOKUP_FILTER_RANGE,
                LOOKUP_QUERY_IN,
                # to search elements greater than the given value
                LOOKUP_QUERY_GT,
                # to search for the elements equal and greater than the given value
                LOOKUP_QUERY_GTE,
                # to search for the elements lesser than the given value
                LOOKUP_QUERY_LT,
                # to search for the elements equal and lesser than the given value.
                LOOKUP_QUERY_LTE,
            ],
        },
        'title': 'title.raw',
        'content': 'content.raw',
        'color': 'color.raw',
    }

    # set ordering fields
    ordering_fields = {
        'title': 'title.raw',
        'content': 'content.raw',
        'color': 'color.raw',

    }

    functional_suggester_fields = {
        'title': 'title.raw',
        'content': 'content.raw',
    }



