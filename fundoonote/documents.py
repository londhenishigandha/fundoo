@article_index.doc_type
class ArticleDocument(DocType):
    """Article elasticsearch document"""

    id = fields.IntegerField(attr='id')
    title = fields.StringField(
        analyzer=html_strip,
        fields={
            'raw': fields.StringField(analyzer='keyword'),
        }
    )
    body = fields.TextField(
        analyzer=html_strip,
        fields={
            'raw': fields.TextField(analyzer='keyword'),
        }
    )
    author = fields.IntegerField(attr='author_id')
    created = fields.DateField()
    modified = fields.DateField()
    pub_date = fields.DateField()

    class Meta:
        model = models.Notess