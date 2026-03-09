from rest_framework import serializers
from account.utils import Util
from .models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode ,urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "password2", "tc"]
        extra_kwargs = {"password": {"write_only": True}}

    # Validating Password and Confirm Password while Registering
    
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        return data
    
    """ Bcz u're creating a custom model"""
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        model = User
        fields = ['email', 'password']
        
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name"]
        
class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    
    class Meta:
        fields = ["password", "password2"]
        
    def validate(self, data):
        password = data.get("password")
        password2 = data.get("password2")
        user = self.context.get('user') # Extract the user
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return data 
                 
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']
    
    def validate(self, data):
        email = data.get("email")
        if User.objects.filter(email=email).exists(): # see if the user exists
            user = User.objects.get(email=email) # Get the user
            uid = urlsafe_base64_encode(force_bytes(user.id)) # convert user id to bytes and encode it
            token = PasswordResetTokenGenerator().make_token(user) # create a token to the user
            link = 'http://localhost:3000/api/user/reset-password/' + uid + '/' + token # http://127.0.0.1:8000/api/user/reset-password/Mw/d1ud38-d0c0fca2fa3fc5436b3b1479744c37ce/
            print(link)
            # SEND EMAIL
            body = 'Click Following Link to Reset Your Password. ' + link
            data = {
                'subject':'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return data  
        else:
            raise serializers.ValidationError("You're not a Registered User")

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    
    class Meta:
        fields = ["password", "password2"]
        
    def validate(self, data):
        try:
            password = data.get("password")
            password2 = data.get("password2")
            uid = self.context.get('uid') # Extract the uid it is encoded 
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token): # The user had sent req to reset is that the same user
                raise serializers.ValidationError('Token is not Valid or Expired')
            
            user.set_password(password)
            user.save()
            return data 
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')