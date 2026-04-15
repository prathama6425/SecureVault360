from django.urls import path
from . import views

urlpatterns = [
    path('', views.password_list, name='password_list'),
    path('add/', views.add_password, name='add_password'),
    path('view/<int:pk>/', views.view_password, name='view_password'),
]
