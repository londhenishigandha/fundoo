from django.contrib.auth.models import User
from .models import Account
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from .models import Notes
from .models import Labels
from django_elasticsearch_dsl_drf.serializers import DocumentSerializer
# from .documents import NotesDocument


class RegisterSerializer(serializers.ModelSerializer):

    firstname = serializers.CharField(required=False)
    lastname = serializers.CharField(required=False)
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=Account.objects.all())])
    username = serializers.CharField(validators=[UniqueValidator(queryset=Account.objects.all())])
    password = serializers.CharField(min_length=8)

    class Meta:
        model = Account
        fields = ('firstname', 'lastname', 'email', 'username', 'password',)

    def create(self, validated_data):
        user = Account.objects.create(**validated_data)
        user.is_active = False
        user.set_password(user.password)
        user.save()
        return user


class NoteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notes
        fields = ('id', 'title', 'content', 'created_at', 'updated_at', 'image', 'color', 'is_archive', 'is_pin',
                  'is_trash', 'created_by', 'reminder', 'label', 'collaborate')


class LabelSerializer(serializers.ModelSerializer):

    class Meta:
        model = Labels
        fields = ('id', 'label')
#
#
# class NotesDocumentSerializer(DocumentSerializer):
#     title = serializers.CharField(read_only=True)
#     content = serializers.CharField(read_only=True)
#     color = serializers.CharField(read_only=True)
#
#     class Meta:
#         document = NotesDocument
#         fields = ('id', 'title', 'content', 'color')
#
