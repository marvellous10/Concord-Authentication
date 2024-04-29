from mongoengine import *


class CandidateUser(Document):
    name = StringField(required=True)
    phone_number = StringField(min_length=10, max_length=12, required=True, unique=True)
    password = StringField(required=True)
    email = EmailField(unique=True, required=True)
    access_token = StringField(default='none')
    
    meta = {
        'collection': 'CandidateUsers'
    }
