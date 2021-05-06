from django.shortcuts import render
from django.contrib.auth import authenticate
from rest_framework import status,exceptions
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer, CreateUserSerializer, LoginSerializer, PasswordSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from rest_framework.generics import GenericAPIView

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
        else:
            raise PermissionDenied('Old password is same as New password')

        response = {
            'status':'Success',
        }

        return Response(response, 200)