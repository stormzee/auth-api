from django.contrib import admin
from django.urls import path
from .views import User_create_view,CreateUserView,UserLoginView,PasswordChangeView, PasswordResetConfirmView,PasswordResetEmailView
from rest_framework.schemas import get_schema_view

urlpatterns = [

    path('Users/',User_create_view.as_view(), name='Users'),
    path('register/',CreateUserView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('password/', PasswordChangeView.as_view(),name='change-password'),
    path('password-reset-email/',PasswordResetEmailView.as_view(), name='password-reset-email'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # ...
    # Use the `get_schema_view()` helper to add a `SchemaView` to project URLs.
    #   * `title` and `description` parameters are passed to `SchemaGenerator`.
    #   * Provide view name for use with `reverse()`.
    path('', get_schema_view(title="Full Authentication API",
    description="API for all user authentication",version="1.0.0"), 
    name='openapi-schema'),
    # ...
]
