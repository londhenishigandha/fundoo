from .models import UserProfileInfo
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


# User form
class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        model = User
        fields = ('username', 'password', 'email')


class UserProfileInfoForm(forms.ModelForm):

    class Meta:
        model = UserProfileInfo
        fields = ('portfolio_site', 'profile_pic')

#
# # sign up form
# class SignupForm(UserCreationForm):
#     #  email field take email address while registering for email confirmation.
#     email = forms.EmailField(max_length=200, help_text='Required')
#
#     class Meta:
#         model = User
#         fields = ('username', 'email', 'password1', 'password2')


class SignupForm(UserCreationForm):

    email = forms.EmailField(max_length=200, help_text='Required')

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')