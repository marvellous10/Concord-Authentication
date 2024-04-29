from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('adminauth/', include('Adminauthentication.urls')),
    path('candidateauth/', include('Candidateauthentication.urls')),
]
