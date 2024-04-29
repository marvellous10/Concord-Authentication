from rest_framework import serializers
from .models import *

class CandidateUserSerializer(serializers.Serializer):
    name = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField()
    access_token = serializers.CharField(default='none')
    phone_number = serializers.CharField()
    
    def create(self, validated_data):
        return CandidateUser.objects.create(**validated_data)