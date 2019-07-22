from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import Notess
from .models import Labels
from django_elasticsearch_dsl_drf.serializers import DocumentSerializer
from .documents import NotesDocument


# class LoginSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ('username', 'password')


class RegisterSerializer(serializers.ModelSerializer):

    first_name = serializers.CharField()
    last_name = serializers.CharField()
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
    username = serializers.CharField(validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(min_length=8)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'username', 'password',)

    def create(self, validated_data):
        user = User.objects.create(**validated_data)
        user.is_active = False
        user.set_password(user.password)
        user.save()
        return user


class NoteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notess
        fields = ('id', 'title', 'content', 'created_at', 'updated_at', 'image', 'color', 'is_archive', 'is_pin', 'is_trash', 'created_by', 'collaborate')


class LabelSerializer(serializers.ModelSerializer):

    class Meta:
        model = Labels
        fields = ('id', 'label')


class NotesDocumentSerializer(DocumentSerializer):
    title = serializers.CharField(read_only=True)
    content = serializers.CharField(read_only=True)
    color = serializers.CharField(read_only=True)

    class Meta:
        document = NotesDocument
        fields = ('id', 'title', 'content', 'color')


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=100)

    class Meta:
        model = User
        fields =('username', 'password')