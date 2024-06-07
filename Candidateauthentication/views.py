from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


import jwt
import os
from dotenv import load_dotenv
from datetime import datetime as dt, timedelta, timezone
from django.contrib.auth.hashers import make_password, check_password
from pymongo import MongoClient

from .models import *
from .serializers import *



class Signup(APIView):
    def post(self, request, format=None, *args, **kwargs):
        email = request.data.get('email')
        name = request.data.get('name')
        password = request.data.get('password')
        phone_number = request.data.get('phone_number')
        
        encrypted_password = make_password(password=password)
        
        try:
            candidate_user = CandidateUser.objects.filter(phone_number=phone_number)
            candidate_user_email_check = CandidateUser.objects.filter(email=email)
        except Exception as e:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'An error occurred, please try again later'
                },
                status=status.HTTP_408_REQUEST_TIMEOUT
            )
        
        if candidate_user or candidate_user_email_check:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'This user already exists'
                },
                status=status.HTTP_405_METHOD_NOT_ALLOWED
            )
        
        user_data= {
            "name": name,
            "email": email,
            "password": encrypted_password,
            "phone_number": phone_number
        }
        
        candidate_serializer = CandidateUserSerializer(data=user_data)
        try:
            if candidate_serializer.is_valid(raise_exception=True):
                candidate_serializer.save()
            
                return Response(
                    {
                        'status': 'Passed',
                        'message': 'You have successfully registered'
                    },
                    status=status.HTTP_201_CREATED
                )
            else:
                return Response(
                    {
                        'status': 'Failed',
                        'message': 'An error occurred'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'An error occured'
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class Login(APIView):
    def post(self, request, format=None, *args, **kwargs):
        load_dotenv()
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')
        voting_code = request.data.get('voting_code')
        
        host = os.getenv('DATABASE_URI')
        client = MongoClient(host=host, port=27017)
        database = client['voting-system']
        votingdb_collection = database['VotingDB']
        votingdb_session_details = votingdb_collection.find_one(
            {
                'voting_code': voting_code
            }
        )
        code_index = 0
        code = ''
        if votingdb_session_details:
            voting_detail = votingdb_session_details
        else:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'Voting code not found'
                },
                status=status.HTTP_404_NOT_FOUND
            )
        if phone_number not in voting_detail['allowed_phone_numbers']:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'You are not allowed to join this session'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        if phone_number in voting_detail["candidates_voted"]:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'You have already voted'
                },
                status=status.HTTP_406_NOT_ACCEPTABLE
            )
        if voting_detail["open_session"] == False:
            return Response(
                {
                    'status': 'Failed',
                    'message': 'Voting session is closed right now'
                },
                status=status.HTTP_405_METHOD_NOT_ALLOWED
            )
        try:
            try:
                candidate_user = CandidateUser.objects.filter(phone_number=phone_number).first()
            except Exception as e:
                return Response(
                    {
                        'status': 'Failed',
                        'message': 'An error occurred, please try again later'
                    },
                    status=status.HTTP_408_REQUEST_TIMEOUT
                )
            if not candidate_user:
                return Response(
                    {
                        'status': 'Failed',
                        'message': 'User does not exist'
                    },
                    status=status.HTTP_404_NOT_FOUND
                )
                
            if not check_password(password=password, encoded=candidate_user.password):
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
                    'phone_number': candidate_user.phone_number,
                    'admin': False,
                    'voting_code': voting_code,
                },
                'iat': dt.now(timezone.utc),
                'exp': dt.now(timezone.utc)+ timedelta(hours=4)
            }
                
            encoded_jwt_token = jwt_instance.encode(payload=message, key=jwt_key, algorithm='HS256')
            
            candidate_user.access_token = encoded_jwt_token
            candidate_user.save()
                
            first_name = candidate_user.name.split()[0]
            
            voting_session_detail = {
                "session_name": voting_detail['session_name'],
                "voting_code": voting_detail['voting_code'],
                "positions": voting_detail['positions']
            }
                
            return Response(
                {
                    'status': 'Passed',
                    'message': encoded_jwt_token,
                    'display_name': first_name,
                    'voting_details': voting_session_detail
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {
                    'status': 'Failed',
                    'message': e
                },
                status=status.HTTP_408_REQUEST_TIMEOUT
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
        candidate_user = CandidateUser.objects.filter(phone_number=phone_number).first()
        if candidate_user:
            if candidate_user.access_token == 'none':
                return Response('User is logged out')
            candidate_user.access_token = 'none'
            candidate_user.save()
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