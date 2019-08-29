# from elasticsearch_dsl import analyzer
#
# from django_elasticsearch_dsl import Index
#
# note_index = Index('notes')
# note_index.settings(
#     # the number of primary shards
#     number_of_shards=1,
#     # the number of replica shards
#     number_of_replicas=1
#     )
#
# html_strip = analyzer(
#     # html_strip filter strips HTML elements from the text and replaces HTML entities with their decoded value
#     'html_strip',
#     # it returns a single term/ it split string into words
#     tokenizer="standard",
#     filter=["standard", "lowercase", "stop", "snowball"],
#     # replacing a particular character with words
#     char_filter=["html_strip"]
#     )