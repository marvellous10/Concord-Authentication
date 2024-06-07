from mongoengine import *

class AdminUser(Document):
    email = EmailField(required=True, unique=True)
    phone_number = StringField(required=True, unique=True, min_length=10, max_length=12)
    name = StringField(required=True)
    password = StringField(required=True)
    access_token = StringField(default='none')
    #voting_code = ListField(DictField(), required=False)
    
    meta = {
        'collection': 'AdminUsers'
    }
