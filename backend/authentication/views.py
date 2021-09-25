from authentication.models import User
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    RegisterSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
    LogoutSerializer,
    ChangePasswordSerializer
)
from .renderers import UserRenderer
from .utils import Util
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.conf import settings
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import smart_bytes, smart_str,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.permissions import IsAuthenticated
import jwt

import environ

env = environ.Env()
environ.Env.read_env()
# Register View
class RegisterView(generics.GenericAPIView):
    
    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self,request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data

        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')

        absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)

        email_body = "Hi "+user.email + " Use the below link to verify your email\n"+absurl
        data = {
            'to_email':user.email,
            'email_body':email_body,
            'email_subject':"Verify your email!!"
        }
        Util.send_email(data)

        return Response(user_data,status=status.HTTP_201_CREATED)



# Verify Email View
class VerifyEmail(APIView):
    
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token',in_=openapi.IN_QUERY,description='Description',type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self,request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY,algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()

            return redirect(env('FRONTEND_URL')+"login/?token_valid=True")

        except jwt.ExpiredSignatureError as identifier:
            return redirect(env('FRONTEND_URL')+"?token_valid=False")
        except jwt.exceptions.DecodeError as identifier:
            return redirect(env('FRONTEND_URL')+"?token_valid=False")


class LoginView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):

        user = request.data
        
        serilaizer = self.serializer_class(data=user)
        serilaizer.is_valid(raise_exception=True)

        return Response(serilaizer.data, status=status.HTTP_200_OK)



class ResetPasswordView(generics.GenericAPIView):
    
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('confirm-password-reset',kwargs={'uidb64':uidb64,'token':token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://' + current_site + relativeLink
            email_body = "Hello,\n Use the below link to reset your password\n"+absurl+"?redirect_url="+redirect_url
            data = {
                'to_email':email,
                'email_body':email_body,
                'email_subject':"Reset your password!!"
            }
            Util.send_email(data)
        return Response({'success':'Email has been sent with password reset link!'}, status=status.HTTP_200_OK)



class PasswordTokenCheckApi(generics.GenericAPIView):

    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user,token=token):

                if len(redirect_url)>3:

                    return redirect(redirect_url+"?token_valid=False")
                else:
                    return redirect(env('FRONTEND_URL')+"?token_valid=False")
            if redirect_url and len(redirect_url)>3:
                return redirect(redirect_url+"?token_valid=True&uidb64="+uidb64+"&token="+token)
            else:
                return redirect(env('FRONTEND_URL')+"?token_valid=False")
        except DjangoUnicodeDecodeError as identifier:
            return redirect(redirect_url+"?token_valid=False")



class SetNewPasswordApiView(generics.GenericAPIView):

    serializer_class = SetNewPasswordSerializer

    def patch(self,request):
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({'success':True, 'message':'password successfully reset!'}, status=status.HTTP_200_OK)


class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = (IsAuthenticated,)

    def patch(self,request):
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({'success':True, 'message':'password successfully changed!'}, status=status.HTTP_200_OK)


class LogoutApiView(generics.GenericAPIView):

    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)


    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


class HelloWorldView(APIView):

    def get(self, request):
        return Response(data={"hello":"world"}, status=status.HTTP_200_OK)