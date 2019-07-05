from rest_framework import serializers
from .models import Notes


class NoteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notes
        fields = ('id', 'title', 'content', 'created_at', 'updated_at', 'image', 'color', 'is_archive', 'is_pin', 'is_trash')


class LabelSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notes
        fields = ('id', 'title')