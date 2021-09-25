from django.urls import path
from .views import (
    RegisterView,
    VerifyEmail,
    LoginView,
    ResetPasswordView,
    PasswordTokenCheckApi,
    SetNewPasswordApiView,
    ChangePasswordView,
    LogoutApiView,
    HelloWorldView
)
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('register/',RegisterView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('email-verify/',VerifyEmail.as_view(),name='email-verify'),
    path('request-password-reset/',ResetPasswordView.as_view(), name='request-password-reset'),
    path('confirm-password-reset/<uidb64>/<token>/',PasswordTokenCheckApi.as_view(),name='confirm-password-reset'),
    path('complete-password-reset/',SetNewPasswordApiView.as_view(),name='complete-password-reset'),
    path('change-password/',ChangePasswordView.as_view(),name='change-password'),
    path('logout/',LogoutApiView.as_view(),name='logout'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('hello/', HelloWorldView.as_view(), name='hello'),
]