from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
#from rest_framework.exceptions import AuthenticationFailed

import os
import jwt
from dotenv import load_dotenv
from datetime import datetime as dt, timezone, timedelta
from django.contrib.auth.hashers import make_password, check_password

from .models import *
from .serializers import *


class Signup(APIView):
    def post(self, request, format=None, *args, **kwargs):
        name = request.data.get('name')
        email = request.data.get('email')
        password = request.data.get('password')
        phone_number = request.data.get('phone_number')
        encrypted_password = make_password(password)
        
        user_data = {
            "name": name,
            "email": email,
            "phone_number": phone_number,
            "password": encrypted_password,
            "voting_code": []
        }
        try:
            adminuser_serializer = AdminUserSerializer(data=user_data)
            if adminuser_serializer.is_valid(raise_exception=True):
                try:
                    adminuser = AdminUser.objects.filter(phone_number=phone_number)
                except Exception as e:
                    return Response(
                        {
                            'status': 'Failed',
                            'message': 'An error occurred, please try again'
                        },
                        status=status.HTTP_408_REQUEST_TIMEOUT
                    )
                if adminuser:
                    return Response(
                        {
                            'status': 'Failed',
                            'message': 'The user already exists'
                        },
                        status=status.HTTP_405_METHOD_NOT_ALLOWED)
                adminuser_serializer.save()
                return Response(
                    {
                        'status': 'Passed',
                        'message': 'You have registered successfully'
                    },
                    status=status.HTTP_201_CREATED)
            else:
                return Response(
                    {
                        'status': 'Failed',
                        'message': 'An error occurred, please try again later'
                    },
                    status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            raise Exception(e)
        
class Login(APIView):
    def post(self, request, format=None, *args, **kwargs):
        load_dotenv()
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')
        
        try:
            adminuser = AdminUser.objects.filter(phone_number=phone_number).first()
        except Exception as e:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'An error occurred, please try again'
                },
                status=status.HTTP_408_REQUEST_TIMEOUT
            )
        if not adminuser:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'User does not exist'
                },
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not check_password(password=password, encoded=adminuser.password):
            return Response(
                {
                    'status': 'Failed',
                    'message': 'Incorrect password'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        jwt_instance = jwt
        jwt_key = os.getenv('JWT_ENCODING_KEY')
        
        message = {
            'message_info': {
                'phone_number': adminuser.phone_number,
                'admin': True
            },
            'iat': dt.now(timezone.utc),
            'exp': dt.now(timezone.utc)+ timedelta(hours=4)
        }
        
        encoded_jwt_token = jwt_instance.encode(payload=message, key=jwt_key, algorithm='HS256')
        
        adminuser.access_token = encoded_jwt_token
        adminuser.save()
        display_name = adminuser.name.split()[0]
        
        return Response(
            {
                'status': 'Passed',
                'message': encoded_jwt_token,
                'display_name': display_name
            },
            status=status.HTTP_200_OK
        )
        
class Logout(APIView):
    def post(self, request, format=None, *args, **kwargs):
        load_dotenv()
        token_number = request.data.get('access_token')
        try:
            decoded_token = jwt.decode(token_number, os.getenv('JWT_ENCODING_KEY'), algorithms=['HS256'])
        except jwt.ExpiredSignatureError as jwte:
            return Response(
                {
                    'message': 'Please log in again'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        phone_number = decoded_token["message_info"]["phone_number"]
        adminuser = AdminUser.objects.filter(phone_number=phone_number).first()
        if adminuser:
            if adminuser.access_token == 'none':
                return Response('User is logged out')
            adminuser.access_token = 'none'
            adminuser.save()
            return Response(
                {
                    'message': 'You have logged out'
                },
                status=status.HTTP_202_ACCEPTED
            )
        else:
            return Response(
                {
                    'message': 'User does not exist'
                },
                status=status.HTTP_400_BAD_REQUEST
            )