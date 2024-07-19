from django.urls import path
from .views import home, convert_passwords, identify_hash

urlpatterns = [
    path('', home, name='home'),
    path('convert/', convert_passwords, name='convert_passwords'),
    path('identify-hash/', identify_hash, name='identify_hash'),
]
