import jwt
from django.http import HttpResponse
from self import self
from .models import Account
from .service import redis_methods


def my_login_required(function):

    def verification(reference):
        redistoken = redis_methods.get_token(self, 'token')   # gets the token from the redis cache
        # print("get the  Token", redistoken)
        # decodes the token
        decoded_token = jwt.decode(redistoken, 'secret', algorithms=['HS256'])
        # decodes the jwt token and gets the value of user details
        # print("TOKEN DECODE", decoded_token)
        user_id = decoded_token.get('id')
        user = Account.objects.get(id=user_id)
        print("user name", user)
        if user:
            # if it is present then go to next stp
            return function(reference)
        else:
            raise PermissionError  # raises the permission error
    return verification
