from rest_framework import serializers
from .models import User



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


class PasswordSerializer(serializers.ModelSerializer):
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

class PasswordResetSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(required=True)
    password2 = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['password1', 'password2']
        extra_kwargs = {
            'password1':{
                'write_only':True
            },

            'password2':{
                'write_only':True
            }
        }
    