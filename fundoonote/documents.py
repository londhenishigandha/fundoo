from django_elasticsearch_dsl import DocType, Index, fields
from .index import note_index, html_strip
from .models import Notess
from elasticsearch_dsl.connections import connections

# to create a connections
connections.create_connection(hosts=['localhost'])
# to get the connections
connections.get_connection().cluster.health()
notes = Index('notes')


@note_index.doc_type
class NotesDocument(DocType):
    title = fields.StringField(
        # analyzer: Split the piece of text into individual token
        analyzer=html_strip,
        fields={
            'raw': fields.StringField(analyzer='keyword'),
        }
    )
    content = fields.TextField(
        analyzer=html_strip,
        fields={
            'raw': fields.TextField(analyzer='keyword'),
        }
    )
    color = fields.StringField(
        analyzer=html_strip,
        fields={
            'raw': fields.StringField(analyzer='keyword'),
        }
    )
    created_at = fields.DateField()

    class Meta(object):
        model = Notess
