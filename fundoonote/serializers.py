from rest_framework import serializers
from .models import Notess
from .models import Labels
from django_elasticsearch_dsl_drf.serializers import DocumentSerializer
from fundoonote import documents as documents


class NoteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notess
        fields = ('id', 'title', 'content', 'created_at', 'updated_at', 'image', 'color', 'is_archive', 'is_pin', 'is_trash')


class LabelSerializer(serializers.ModelSerializer):

    class Meta:
        model = Labels
        fields = ('id', 'label')


class ArticleDocumentSerializer(DocumentSerializer):
    class Meta:
        document = documents.Document
        fields = (
            'id',
            'title',
            'content',
            'color',
            'image',
        )