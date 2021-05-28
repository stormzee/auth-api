from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import PermissionDenied
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework import exceptions
from .models import User
from django.utils.encoding import (
    DjangoUnicodeDecodeError, force_text, smart_str, smart_bytes, force_str, force_bytes
)
class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = "__all__"
        read_only_fields = ['id','username','is_staff','is_superuser',
        'user_permissions','groups','last_login','is_admin']
        extra_kwargs = {
            'password':{
                'write_only':True
            }
        }

class CreateUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['username','password','email']
        extra_kwargs = {
            'password':{
                'write_only':True
            }
        }

    def create(self, validated_data):
        username = self.validated_data.get('username')
        email = self.validated_data.get('email')
        password = self.validated_data.get('password')
        user = User(username=username, email=email)
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['username', 'password']
        read_only_fields = ['id','is_staff','is_admin','username','email','password']
        extra_kwargs = {
            'password':{
                'write_only':True
            }
        }


class PasswordChangeSerializer(serializers.ModelSerializer):
    new_password = serializers.CharField(required=True)
    old_password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['new_password','old_password']
        extra_kwargs = {
            'new_password':{
                'write_only':True
            },
            'old_password':{
                'write_only':True
            }
        }

class PasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=200, required=True)

    class Meta:
        fields = ['email']

# Get the user by email
# encode user's id in uidb64 format
# encode the token and send them(id,token) as part of the email
            
class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True, write_only=True)
    token = serializers.CharField(required=True)
    uidb64 = serializers.CharField(required=True)

    class Meta:
        fields = ['new_password', 'token', 'uidb64']
        extra_kwargs = {
            'new_password':{
                'write_only':True
            }
        }

# validating credentials in the backend
    def validate(self, attrs):
        try:
            password = attrs.get('new_password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            user_id = force_str(urlsafe_base64_decode(uidb64))

            user = User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                print('error here')
                raise exceptions.PermissionDenied('Invalid Credentials')

            user.set_password(password)
            user.save()

            return user
        except Exception as error:
            raise exceptions.PermissionDenied('Invalid Credentials')

        return super().validate(attrs)

    