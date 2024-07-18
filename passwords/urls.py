from django.urls import path
from passwords import views

urlpatterns = [
    path('', views.home, name='home')
]


