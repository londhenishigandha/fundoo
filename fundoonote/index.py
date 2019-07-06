from elasticsearch_dsl import analyzer

from django_elasticsearch_dsl import DocType, Index, fields

from . import models as articles_models

index = Index('fundoonote')
index.settings(
    number_of_shards=1,
    number_of_replicas=0
)

html_strip = analyzer(
    'html_strip',
    tokenizer="standard",
    filter=["standard", "lowercase", "stop", "snowball"],
    char_filter=["html_strip"]
)