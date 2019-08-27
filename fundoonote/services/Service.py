from fundoonote.services.noteServices import NoteServices
from fundoonote.services.userServices import UserService
from fundoonote.models import Account, Notess
from django.core.exceptions import ObjectDoesNotExist


class Service:

    def __init__(self):
        self.note_obj = NoteServices()
        self.user_obj = UserService()

    def collaborate(self, email, note_id):
            note = self.note_obj.get_note(note_id)
            user_collab = self.user_obj.get_user(email)
            if user_collab:
                self.note_obj.collaborate_note(user_collab, note)
            else:
                print("Email is required")

    def allUser(self, email):
        users = self.user_obj.get_user(email)
        self.user_obj.get_user(users)

    def collaborator(self, email, note_id):
        try:

            collaborate_user = Account.objects.filter(email=email, is_active=True)
            if not collaborate_user:
                raise ObjectDoesNotExist("User Not Exist..")

            note_obj = Notess.objects.get(id=note_id)
            if not note_obj:
                raise ObjectDoesNotExist("Note not exist..")

            note_obj.collaborate.add(collaborate_user)
            if note_obj:
                return True

        except ObjectDoesNotExist as e:
            print(e)
        return False

