from django.urls import path
from .views import *


urlpatterns = [
    path('signup/', Signup.as_view(), name="adminsignup"),
    path('login/', Login.as_view(), name="adminlogin"),
    path('logout/', Logout.as_view(), name="logout"),
]
