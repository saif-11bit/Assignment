from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
import jwt
from django.conf import settings
# User Registraion Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68,min_length=6,write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password']

    
    def validate(self, attrs):
        email = attrs.get('email', '')

        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


# Verify Email once registered
class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=2000)

    class Meta:
        model = User
        fields = ['token']



class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=200)
    password = serializers.CharField(min_length=6, max_length=200,write_only=True)
    token = serializers.SerializerMethodField()

    def get_token(self,obj):
        user = User.objects.get(email=obj['email'])

        return {
            'access':user.tokens()['access'],
            'refresh':user.tokens()['refresh'],
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'token']

    
    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email,password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials.Try again!')

        if not user.is_active:
            raise AuthenticationFailed('Account not active.Contact admin!')
        
        if not user.is_verified:
            raise AuthenticationFailed('Please Verify your email!')
        
        return {
            'email':user.email,
            'token':user.tokens,
        }


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=244)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6,max_length=100,write_only=True)
    token = serializers.CharField(min_length=2,max_length=1000,write_only=True)
    uidb64 = serializers.CharField(min_length=1,write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link invalid!',401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link invalid!',401)



class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6,max_length=100,write_only=True)
    token = serializers.CharField(min_length=2,max_length=1000,write_only=True)
    class Meta:
        fields = ['password','token']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            payload = jwt.decode(token, settings.SECRET_KEY,algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])

            user.set_password(password)
            user.save()

            return (user)

        except jwt.ExpiredSignatureError as identifier:
            raise DjangoUnicodeDecodeError('Something went wrong!')
        except jwt.exceptions.DecodeError as identifier:
            raise DjangoUnicodeDecodeError('Something went wrong!')

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token':'Token is expired or invalid!'
    }

    def validate(self, attrs):
        self.token = attrs['refresh']

        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError as e:
            self.fail('bad_token')