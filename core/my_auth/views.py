from django.shortcuts import render
from django.contrib.auth import authenticate, update_session_auth_hash
from rest_framework import status,exceptions
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import (UserSerializer, CreateUserSerializer, 
        LoginSerializer, PasswordSerializer, 
        PasswordResetSerializer
        )
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from rest_framework.generics import GenericAPIView
from b64uuid import B64UUID
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.conf import settings


class User_create_view(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserSerializer

    def get(self, request):
        user = request.user
        response ={
        'data':UserSerializer(user).data,
        'auth':str(request.auth),
        'status':'Success'
        }
        return Response(response,201)


class CreateUserView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = CreateUserSerializer



    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        response = {
            'data':serializer.data,
            'status':'created'
        }

        return Response(response, 201)


class UserLoginView(GenericAPIView):

    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(request, username=serializer.validated_data['username'],
         password=serializer.validated_data['password'])
        if user is None:
            raise exceptions.PermissionDenied('No user with the given credentials exists ')
        try:
            refresh = RefreshToken.for_user(user)
            jwt_token = refresh.access_token
        except User.DoesNotExist:
            raise exceptions.PermissionDenied('No user with these details exists')

        response = {
            'refresh_token':str(refresh),
            'access_token':str(jwt_token),
            'data': UserSerializer(user).data,
            'status':'Success'
        }

        return Response(response,200)



class PasswordChangeView(GenericAPIView):
    serializer_class = PasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        user = request.user
        new_pass = serializer.validated_data.get('new_password')
        old_pass = serializer.validated_data.get('old_password')
        if new_pass != old_pass:
            user.set_password(new_pass)
            user.save()
            # make sure the user is not logged out after changing the password.
            update_session_auth_hash(request, user)
        else:
            raise PermissionDenied('Old password is same as New password')

        response = {
            'status':'Success',
        }

        return Response(response, 200)

class PasswordResetView(GenericAPIView):
    Serializer_class = PasswordResetSerializer
    peremission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user = request.user
        email = user.email
        # generate a token to be sent via email
        token = str(RefreshToken.for_user(user).access_token)
        uid = str(B64UUID(user.id))
        domain = str(get_current_site(request).domain)
        abs_url = f'http//+{domain}+?uid={uid}+?token={token}'
        msg_body = f'Hello {user.username}, please reset your password by clicking on the link below\n{abs_url}'
        subject = f'{domain} Password Reset Link'
        send_mail(
            subject=subject,
            message = msg_body,
            From = settings.EMAIL_HOST_USER,
            To = email
        )

        return Response()
