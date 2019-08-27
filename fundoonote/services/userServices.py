from fundoonote.models import Account


class UserService:

    def get_user(self, user):
        return Account.objects.get(email=user)
