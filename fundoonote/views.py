import json
import os
import pickle
import redis
from boto3.s3.transfer import S3Transfer
import logging
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
from .serializers import NoteSerializer, NotesDocumentSerializer, RegisterSerializer
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
from .models import Account
from fundoonote.services.Service import Service
logger = logging.getLogger(__name__)


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
    request_data = json.loads((request.body).decode('utf-8'))
    print(type(request_data), '------------>')
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
                        'email': user.email,
                        'first_name': user.firstname,
                        'last_name': user.lastname,
                        'jwt_token': jwt_token
                }
                print(result)
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
                print(serializer.data)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors)


@csrf_exempt
def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = Account.objects.get(pk=uid)
        print(user)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
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
            user = Account.objects.get(email=email)
            print(user)
            current_site = get_current_site(request)
            mail_subject = "Reset your password"
            # create the email body with activation link
            message = render_to_string("acc_active_email.html", {
                'user': user,  # pass the user
                'domain': 'localhost:3000/resetpassword',  # pass the current domail
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
            return HttpResponse({"abc": "Fail"})


@csrf_exempt
def forgot_pass_activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = Account.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
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
        user = Account.objects.get(pk=uid)
        print(user)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
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
    permission_classes = [AllowAny]

    def get(self, request):
        redistoken = redis_methods.get_token(self, 'token')  # gets the token from the redis cache
        print("get the  Token", redistoken)
        # decodes the token
        decoded_token = jwt.decode(redistoken, 'secret', algorithms=['HS256'])
        # decodes the jwt token and gets the value of user details
        user_id = decoded_token.get('id')
        user = Account.objects.get(id=user_id)
        # print("Name of the user: ", user)
        notes = Notess.objects.filter(is_trash=False, created_by=user, is_archive=False, is_pin=False).order_by('id')
        # print("note", notes)
        # labels= Labels.objects.filter(id=user_id)
        serializer = NoteSerializer(notes, many=True).data
        length = len(serializer)
        # print(length, '------------->')
        my_labels = []
        for index in range(0, length):
            if len(serializer[index]['label']) is not 0:
                for lb in range(0, len(serializer[index]['label'])):
                    label_id = serializer[index]['label'].pop(lb)
                    # print(serializer[index]['label'])
                    label_name = Labels.objects.get(id=label_id).label
                    # print(label_name)
                    serializer[index]['label'].insert(0, label_name)
        # print(length, '------------->')
        # for collaborate
        for index in range(0, length):
            if len(serializer[index]['collaborate']) is not 0:
                for lb in range(0, len(serializer[index]['collaborate'])):
                    label_id = serializer[index]['collaborate'].pop(lb)
                    print(serializer[index]['collaborate'])
                    label_name = Account.objects.get(id=label_id).email
                    print(label_name)
                    serializer[index]['collaborate'].insert(0, label_name)
        r = redis.StrictRedis('localhost')
        mydict = notes
        p_mydict = pickle.dumps(mydict)
        r.set('mydict', p_mydict)
        read_dict = r.get('mydict')
        yourdict = pickle.loads(read_dict)
        # print("Notes in redis cache", yourdict)

        return Response(serializer, status=200)

    def post(self, request):
        restoken = redis_methods.get_token(self, 'token')
        decoded_token = jwt.decode(restoken, 'secret', algorithms=['HS256'])
        print("decode token ", decoded_token)
        dec_id = decoded_token.get('id')
        print("user id", dec_id)
        user = Account.objects.get(id=dec_id)
        print("username", user)
        serializer = NoteSerializer(data=request.data)
        print("dataaaa", serializer)
        print("username", serializer.is_valid())
        print("username...", serializer.errors)
        try:
            if serializer.is_valid():
                serializer.save(created_by=user)
        except serializers.ValidationError:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.data)


# to update and delete the note
class NoteDetailView(APIView):

    def get_object(self, id=None):
        try:
            a = Notess.objects.get(id=id)
            return a
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, request, id=None):
        notes = self.get_object(id)
        serializer = NoteSerializer(notes).data
        return Response(serializer)

    def put(self, request, id=None):
        data = request.data
        instance = self.get_object(id)
        serializer = NoteSerializer(instance, data=data, partial=True)
        print(data)
        print(serializer.is_valid())
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
class ArchiveGetNotes(APIView):

    def get(self, request):
        notes = Notess.objects.filter(is_archive=True)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)


class ArchieveNote(APIView):

    def get_object(self, id=None):
        try:
            a = Notess.objects.get(id=id)
            return a
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, request, id=None):
        notes = Notess.objects.filter(is_archive=True, id=id)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)

    def put(self, request, id=None):
        """  This handles PUT request to achieve particular note by note id  """
        result = {
            "message": "Something bad happened",
            "success": False,
            "data": []
        }
        logger.info("Enter In The PUT Method Set archive API")
        data = request.data['is_archive']
        print("Data", data)
        try:
            if not id:
                raise ValueError
            logger.debug("Enter In The Try Block")
            # get the note object by passing the note id
            instance = self.get_object(id)
            if not instance:
                raise Notess.DoesNotExist
            # check note is not trash and not deleted
            # print(instance, "=====================")
            if not instance.is_archive:
                # update the record and set the archive
                instance.is_archive = data
                instance.save()
                # return the success message and archive data
                result["message"] = "Archive Set Successfully"
                result["success"] = True
                result["data"] = data
                logger.debug("Return The Response To The Browser..")
                return Response(result, status=200)
        # except the exception and return the response
        except ValueError as e:
            result["Message"] = "Note id cant blank"
            logger.debug("Return The Response To The Browser..")
            return Response(result, status=204)
        except Notess.DoesNotExist as e:
            result["message"] = "No record found for note id "
            logger.debug("Return The Response To The Browser..")
        return Response(result, status=204)


class UnArchiveGetNotes(APIView):

    def get(self, request):
        notes = Notess.objects.fUnArchieveNoteilter(is_archive=False)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)


class UnArchieveNote(APIView):

    def get_object(self, id=None):
        try:
            a = Notess.objects.get(id=id)
            return a
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, id=None):
        notes = Notess.objects.filter(is_archive=False, id=id)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)

    def put(self, request, id=None):
        """  This handles PUT request to achieve particular note by note id  """
        result = {
            "message": "Something bad happened",
            "success": False,
            "data": []
        }
        logger.info("Enter In The PUT Method Set archive API")
        data = request.data['is_archive']
        print("Data", data)
        try:
            if not id:
                raise ValueError
            logger.debug("Enter In The Try Block")
            # get the note object by passing the note id
            instance = self.get_object(id)
            if not instance:
                raise Notess.DoesNotExist
            # check note is not trash and not deleted
            # print(instance, "=====================")
            if not instance.is_archive:
                # update the record and set the archive
                instance.is_archive = False
                instance.save()
                # return the success message and archive data
                result["message"] = "UnArchive Set Successfully"
                result["success"] = True
                result["data"] = data
                logger.debug("Return The Response To The Browser..")
                return Response(result, status=200)
        # except the exception and return the response
        except ValueError as e:
            result["Message"] = "Note id cant blank"
            logger.debug("Return The Response To The Browser..")
            return Response(result, status=204)
        except Notess.DoesNotExist as e:
            result["message"] = "No record found for note id "
            logger.debug("Return The Response To The Browser..")
        return Response(result, status=204)


class PinGetNotes(APIView):

    def get(self, request):
        notes = Notess.objects.filter(is_pin=True)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)


# To pin
class pinNote(APIView):

    def get_object(self, id=None):
        try:
            return Notess.objects.get(id=id)
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def put(self, request, id=None):
        """  This handles PUT request to pin particular note by note id  """
        result = {
            "message": "Something bad happened",
            "success": False,
            "data": []
        }
        logger.info("Enter In The PUT Method Set archive API")
        data = request.data['is_pin']
        print("Data", data)
        try:
            if not id:
                raise ValueError
            logger.debug("Enter In The Try Block")
            # get the note object by passing the note id
            instance = self.get_object(id)
            if not instance:
                raise Notess.DoesNotExist
            # check note is not trash and not deleted
            # print(instance, "=====================")
            if not instance.is_pin:
                # update the record and set the archive
                instance.is_pin = data
                instance.save()
                # return the success message and archive data
                result["message"] = "pin Successfully"
                result["success"] = True
                result["data"] = data
                logger.debug("Return The Response To The Browser..")
                return Response(result, status=200)
        # except the exception and return the response
        except ValueError as e:
            result["Message"] = "Note id cant blank"
            logger.debug("Return The Response To The Browser..")
            return Response(result, status=204)
        except Notess.DoesNotExist as e:
            result["message"] = "No record found for note id "
            logger.debug("Return The Response To The Browser..")
        return Response(result, status=204)


class UnPinGetNotes(APIView):

    def get(self, request):
        notes = Notess.objects.filter(is_pin=False)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)


class PinnedNotes(APIView):

    def get(self, request, id=None):
        notes = Notess.objects.filter(is_pin=True)
        # serializer = NoteSerializer(notes, many=True).data
        # notes = Notess.objects.filter(is_trash=False, created_by=user, is_archive=False, is_pin=False).order_by('id')

        # labels= Labels.objects.filter(id=user_id)
        serializer = NoteSerializer(notes, many=True).data
        # print("note==========", serializer)
        length = len(serializer)
        # print(length, '------------->')
        my_labels = []
        for index in range(0, length):
            if len(serializer[index]['label']) is not 0:
                for lb in range(0, len(serializer[index]['label'])):
                    label_id = serializer[index]['label'].pop(lb)
                    # print(serializer[index]['label'])
                    label_name = Labels.objects.get(id=label_id).label
                    # print(label_name)
                    serializer[index]['label'].insert(0, label_name)
        # print(length, '------------->')
        # for collaborate
        for index in range(0, length):
            if len(serializer[index]['collaborate']) is not 0:
                for lb in range(0, len(serializer[index]['collaborate'])):
                    label_id = serializer[index]['collaborate'].pop(lb)
                    print(serializer[index]['collaborate'])
                    label_name = Account.objects.get(id=label_id).email
                    print(label_name)
                    serializer[index]['collaborate'].insert(0, label_name)
        return Response(serializer, status=200)


# To pin
class UnpinNote(APIView):

    def get_object(self, id=None):
        try:
            return Notess.objects.get(id=id)
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, request, id=None):
        notes = Notess.objects.filter(is_pin=False, id=id)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)

    def put(self, request, id=None):
        """  This handles PUT request to pin particular note by note id  """
        result = {
            "message": "Something bad happened",
            "success": False,
            "data": []
        }
        logger.info("Enter In The PUT Method Set archive API")
        data = request.data['is_pin']
        print("Data", data)
        try:
            if not id:
                raise ValueError
            logger.debug("Enter In The Try Block")
            # get the note object by passing the note id
            instance = self.get_object(id)
            if not instance:
                raise Notess.DoesNotExist
            # check note is not trash and not deleted
            print(instance, "=====================")
            if not instance.is_pin:
                # update the record and set the archive
                instance.is_pin = data
                instance.save()
                # return the success message and archive data
                result["message"] = "Unpin Successfully"
                result["success"] = True
                result["data"] = data
                logger.debug("Return The Response To The Browser..")
                return Response(result, status=200)
        # except the exception and return the response
        except ValueError as e:
            result["Message"] = "Note id cant blank"
            logger.debug("Return The Response To The Browser..")
            return Response(result, status=204)
        except Notess.DoesNotExist as e:
            result["message"] = "No record found for note id "
            logger.debug("Return The Response To The Browser..")
        return Response(result, status=204)


# for trash
class TrashView(APIView):
    def get(self, request, is_trash=None):
        notes = Notess.objects.filter(is_trash=True)
        serializer = NoteSerializer(notes, many=True).data
        return Response(serializer, status=200)


class ReminderView(APIView):
    def get(self, request, is_trash=None):
        trashed_notes = Notess.objects.filter(reminder__isnull=False, is_trash=False).order_by('-id')
        serializer = NoteSerializer(trashed_notes, many=True).data
        return Response(serializer, status=200)


# to create a label view
class LabelView(APIView):

    def get(self, request):
        label = Labels.objects.filter(is_deleted=False)
        serializer = LabelSerializer(label, many=True).data
        # print('serializer----<>', serializer)
        length = len(serializer)
        my_labels = []
        for index in range(0, length):
            my_labels.append(serializer[index]['label'])
        # print(my_labels)
        return Response(serializer, status=200)

    def post(self, request):
        print(request.data)
        user = request.user
        print(user)
        serializer = LabelSerializer(data=request.data)
        # print(serializer.errors)
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


class Addlabels(APIView):

    def get_object(self, id=None):
        try:
            a = Labels.objects.get(id=id)
            return a
        except Labels.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get_noteobject(self, id=None):
        try:
            note = Notess.objects.get(id=id)
            return note
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, request, id=None):
        label = self.get_object(id)
        serializer = LabelSerializer(label).data
        return Response(serializer)

    def post(self, request, id=None):
        result = {
            "message": "Something bad happened",
            "success": False,
            "data": []
        }
        print(request.data)
        label_id = request.data.get('label')
        print("----------------->", label_id)
        if not label_id:
            print("error")
        else:
            label_obj = Labels.objects.get(id=label_id)
            print(label_obj)
        if not id:
                print("note id id not valid:")
        else:
            note_obj = Notess.objects.get(id=id)
            print("--------------->", note_obj)
            note_obj.label.add(label_obj)
            note_obj.save()
            print(id)
            return Response("True", status=200)


class DeleteLabel(APIView):

    def put(self, request, id=None):
        print(request.data)
        labelname = request.data.get('label')
        label_obj = Labels.objects.get(label=labelname)
        note_obj = Notess.objects.get(id=id)

        print(label_obj, note_obj, id, labelname)
        if note_obj and label_obj:
            note_obj.label.remove(label_obj.id)
        return Response("Label Deleted", status=200)


class SetReminder(APIView):
    def get_object(self, id=None):
        try:
            a = Notess.objects.get(id=id)
            return a
        except Notess.DoesNotExist as e:
            return Response({"error": "Given object not found."}, status=404)

    def get(self, request, id=None):
        notes = self.get_object(id)
        serializer = NoteSerializer(notes).data
        return Response(serializer)

    def put(self, request, id=None):
        """  This handles PUT request to set the reminder to perticular note by note id  """
        result = {
            "message": "Something bad happened",
            "success": False,
            "data": []
        }
        logger.info("Enter In The PUT Method Set Reminder API")
        print("data=========================", request.data)
        data = request.data['reminder']
        print("Data", data)
        try:
            if not id:
                raise ValueError
            logger.debug("Enter In The Try Block")
            # get the note object by passing the note id
            instance = self.get_object(id)
            if not instance:
                raise Notess.DoesNotExist
            # check note is not trash and not deleted
            if not instance.is_trash:
                # update the record and set the reminder
                instance.reminder = data
                instance.save()
                # return the success message and reminder data
                result["message"] = "Reminder Set Successfully"
                result["success"] = True
                result["data"] = data
                logger.debug("Return The Response To The Browser..")
                return Response(result, status=200)
        # except the exception and return the response
        except ValueError as e:
            result["Message"] = "Note id cant blank"
            logger.debug("Return The Response To The Browser..")
            return Response(result, status=204)
        except Notess.DoesNotExist as e:
            result["message"] = "No record found for note id "
            logger.debug("Return The Response To The Browser..")
        return Response(result, status=204)


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
                    local_path = os.path.join(root, 'sheet.jpeg')
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
            print(uploaded_file)
            if uploaded_file is None:
                message = "Empty file can not be uploaded"
                status_code = 400
                return JsonResponse({'message': message, 'status': status_code})
            else:
                restoken = redis_methods.get_token(self, 'token')
                print('token id', restoken)
                # decoding to get user id and username
                decoded_token = jwt.decode(restoken, 'secret', algorithms=['HS256'])
                print('token', decoded_token)
                decoded_id = decoded_token.get('id')
                user = Account.objects.get(id=decoded_id)
                print('username:', user)
                firstname = user.firstname
                print('name', firstname)
                file_name = user.firstname+".jpg"
                print("File=============", file_name)
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


class Notecollaborator(APIView):

    def get_object(self, id=None):
        obj = Notess.objects.get(id=id)
        return obj

    def put(self, request, id=None):
        """ This handles PUT request to collaborate particular note by note id """
        result = {
            "message": "Something bad happened",
            "success": False,
            "data": []
        }
        logger.info("Enter In The PUT Method collaborate API")
        colobrate_data = request.data
        collaborator_email = colobrate_data['collaborate']
        collaborate_user = Account.objects.filter(email=collaborator_email) & Account.objects.filter(is_active=1)
        # print("collaborate user", collaborate_user)
        user_id = []
        for i in collaborate_user:
            user_id.append(i.id)
        collaborate_id = user_id[0]
        noteinstance = self.get_object(id=id)
        try:
            if not id:
                raise ValueError
            logger.debug("Enter In The Try Block")
            restoken = redis_methods.get_token(self, 'token')
            # decoding to get user id and username
            decoded_token = jwt.decode(restoken, 'secret', algorithms=['HS256'])
            decoded_id = decoded_token.get('id')
            decoded_email = decoded_token.get('email')
            user = Account.objects.get(id=decoded_id)
            if collaborator_email:
                # print("data available in database", collaborator_email)
                if collaborator_email is decoded_email:
                    return Response('with same email id can not be collaborate, Please pass the correct email id')
                else:
                    noteinstance.collaborate.add(int(collaborate_id))
                    noteinstance.save()
                    current_site = get_current_site(request)
                    # creating mail body
                    mail_subject = 'Check collaborated note'
                    message = render_to_string("collaborate_email.html", {
                        'user': user,
                        'domain': current_site.domain,
                    })
                    to_email = collaborator_email
                    email = EmailMessage(
                        mail_subject, message, to=[to_email]
                    )
                    print("email", email)
                    email.send()
                    result["message"] = "Please check your email address to get the collaborated note"
                    result["success"] = True
                    result["data"] = colobrate_data
                    logger.debug("Return The Response To The Browser..")
                    return Response(result, status=200)
            else:
                result["message"] = "User not found"
                result["success"] = True
                result["data"] = colobrate_data
                return Response(result, status=404)
        except ValueError as e:
            result["Message"] = "Note id cant blank"
            logger.debug("Return The Response To The Browser..")
            return Response(result, status=204)
        except Notess.DoesNotExist as e:
            result["message"] = "No record found for note id "
            logger.debug("Return The Response To The Browser..")
        return Response(result, status=200)


class Collaborator(APIView):

    def put(self, request, id=None):
        res = {}
        serv_obj = Service()
        print(request.data)
        collaborator_email = request.data.get('collaborate')
        if not collaborator_email:
            res['msg'] = "Email is required"
            return Response(res, status=200)
        serv_obj.collaborate(collaborator_email, id)
        return Response("collaborator Deleted", status=200)


class AddCollab(APIView):

    def post(self, request, note_id=None):
        res = {
            'message':'',
            'success': False
        }
        try:
            service_obj = Service()
            if not note_id:
                raise ValueError("Note is is required")
            collaborator_email = request.data.get('collaborate')
            if not collaborator_email:
                raise ValueError("Email is required")

            if service_obj.collaborator(collaborator_email, note_id):
                res['message'] = "Note Collaborated.."
                res['success'] = True
                return Response(res, status=200)
            else:
                res['message'] = "failed"
        except Exception as e:
            print(e)

        return Response(res, status=400)


class getAllUser(APIView):
    def get(self, request, id=None):
        user = Account.objects.all()
        data = Account.objects.distinct("email").all()
        collaborate_user = Account.objects.all() & Account.objects.filter(is_active=1)
        users = []
        if data:
            for email in user:
                users.append(email.email)
            user_list = users
        else:
            return Response('Error')
        return Response(user_list)