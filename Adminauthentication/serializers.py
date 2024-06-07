from rest_framework import serializers
from .models import *

class AdminUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    phone_number = serializers.CharField()
    name = serializers.CharField()
    password = serializers.CharField()
    access_token=serializers.CharField(default='none')
    #voting_code = serializers.ListField(child=serializers.DictField(), required=False)
    
    def create(self, validated_data):
        return AdminUser.objects.create(**validated_data)