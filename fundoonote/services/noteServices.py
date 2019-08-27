from fundoonote.models import Account, Notess
from rest_framework.response import Response


class NoteServices:

    def get_note(self, note_id):
        return Notess.objects.get(id=note_id)

    def collaborate_note(self, email, note):
        note.collaborate.add(email)
        note.collaborate.add(email)

    def collaborate(self, request, email, note_id=None):
        colobrate_data = request.data
        collaborator_email = colobrate_data['collaborate']
        collaborate_user = Account.objects.filter(email=collaborator_email) & Account.objects.filter(is_active=1)