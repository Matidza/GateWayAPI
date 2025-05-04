"""  
# Django Core Imports
from django.conf import settings
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.shortcuts import render
from django.utils.crypto import get_random_string
from django.urls import reverse

# Django REST Framework Imports
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.reverse import reverse as drf_reverse
from rest_framework.views import APIView

# JWT Authentication
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication

# Local App Imports
from .serializers import UserSerializer  # Adjust the import as needed
#from .tokens import get_tokens_for_user  # Adjust if using a custom token logic
"""
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

# Django Utilities
from django.shortcuts import render
from django.core.mail import send_mail
from django.utils.crypto import get_random_string

# DRF Imports for Views and Responses
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken 
from rest_framework_simplejwt.authentication import JWTAuthentication

# Serializers
from .serializers import UserSerializer

# Django Model (Optional: for default User model if you need to reference it explicitly)
from django.contrib.auth.models import User
from django.urls import reverse


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.conf import settings

from django.core.mail import send_mail
from django.conf import settings
from django.utils.crypto import get_random_string
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model

from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .serializers import UserSerializer  # Adjust the import as needed
#from .tokens import get_tokens_for_user  # Adjust if you use custom token logic"



## Login User Route
class SigninPageView(APIView):
    'Root route (/) for the API entry point'
    def get(self, request):
        return Response({
            'message': 'Welcome to the API. Use POST to log in.',
            'email': 'Admin@gmail.com', 
            'password': 'Dlta123!@#'
        }, status=status.HTTP_200_OK)

    'Authenticate User To Login'
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Check if user has entered their email and password
        if not email or not password:
            return Response(
                {'message': 'Email and Password are required!'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Authenticate user and serialize the user
        user = authenticate(email=email, password=password)
        serializer = UserSerializer(user, many=False)

        # If user is authenticated, log them in
        if user is not None:
            # Generate token when login is successful
            token = get_tokens_for_user(user)
            login(request, user)
            return Response(
                {'message': 'Login successful', 'user': serializer.data, 'token': token},
                status=status.HTTP_200_OK
            )
        
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    'Forgot Password Route Information'
    def get_forgot_password_info(self, request):
        # You can use Django's reverse to get the route dynamically
        forgot_password_url = reverse('forgot_password')
        return Response(
            {'forgot_password_route': forgot_password_url},
            status=status.HTTP_200_OK
        )

class DashboardView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self,request):
        return Response({
            'message': 'you have access'
        })


User = get_user_model()
password_reset_tokens = {}  # temporary store (in-memory for demo)
## Forgot Password Route(Creates a token and sends it to user)
class ForgotPasswordView(APIView):
    def get(self, request):
        return Response({
            'message': 'Welcome to the API. Use POST to log in.',
            'email': 'Admin@gmail.com'
        }, status=status.HTTP_200_OK)

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({'message': 'Email is required.'},status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            token = get_random_string(length=32)
            password_reset_tokens[email] = token

            message = (
                f"\n\n"
                f"Hi {user},\n\n"
                f"Someone requested a password reset for your Views.com account.\n"
                f"If this wasn't you, ignore this email.\n"
                f"Otherwise, use the token below to reset your password:\n\n"
                f"Token: {token}\n\n"
                f"Thanks,\nThe Views.com Team"
                f"\n\n"
            )
            print(message)
            """  
            send_mail(
                subject="Password Reset Request For Views.com",
                message=message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[email],
                fail_silently=False,
            ) """

            return Response({'message': 'Reset token sent to email.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'message': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

## Rest Password with token Validation
class ResetPasswordView(APIView):
    def get(self, request):
        return Response({
            'message': 'Welcome to the API. Use POST to log in.',
            'email': 'Admin@gmail.com',
            'token': 'Use token that was sent to your email',
            'new_password': 'Enter new password',
            'confirm_password': 'Confirm new password'
            }, status=status.HTTP_200_OK
        )
    
    def post(self, request):
        email = request.data.get("email")
        token = request.data.get("token")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not all([email, token, new_password, confirm_password]):
            return Response(
                {'message': 'All fields are required.'}, 
                status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response(
                {'message': 'Passwords do not match.'}, 
                status=status.HTTP_400_BAD_REQUEST)

        # Verify token
        if password_reset_tokens.get(email) != token:
            return Response(
                {'message': 'Invalid or expired token.'}, 
                status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            user.password = make_password(new_password)
            user.save()
            """   """
            message = (
                f"Hi {user.get_full_name() or user.email},\n\n"
                f"Someone requested a password reset for your Views.com account.\n"
                f"If this wasn't you, ignore this email.\n"
                f"Otherwise, use the token below to reset your password:\n\n"
                f"Token: {token}\n\n"
                f"Thanks,\nThe Views.com Team"
            )
           
            print(message)
            # send email to confirm rest of password
            """  
            send_mail(
                subject="Password Reset",
                message=f"Your password was rest",
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[email],
                fail_silently=False,
            )"""
 
            # Remove token after use
            del password_reset_tokens[email]
            return Response(
                {'message': 'Password has been reset successfully.'}, 
                status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response(
                {'message': 'User not found.'}, 
                status=status.HTTP_404_NOT_FOUND)


# Logout User
class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({
            'message': 'Successfully logged out'
        }, status=status.HTTP_200_OK)
    

# Sign-Up Route
class SignupPageView(APIView):
    def get(self, request):
        return Response(
            {
                'message': 'Welcome to the API. Use POST to register.', 
                'email': 'Admin@gmail.com', 
                'user_type': 'job_seeker',
                'password': 'Dlta123!@#',
                'password1': 'Dlta123!@#'
            }, status=status.HTTP_200_OK
        )
    
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        email = request.data.get("email")
        if serializer.is_valid():
            user = serializer.save()
            token = get_tokens_for_user(user)
            """"  """
            message = (
                f"Hi {user.get_full_name() or user.email},\n\n"
                f"Someone requested a password reset for your Views.com account.\n"
                f"If this wasn't you, ignore this email.\n"
                f"Otherwise, use the token below to reset your password:\n\n"
                f"Token: {token}\n\n"
                f"Thanks,\nThe Views.com Team"
            )
            print()
            # Send email
            """  """
            send_mail(
                subject="Welcome to Views.com!",
                message=message,
                from_email=settings.EMAIL_HOST_USER,  # Or use DEFAULT_FROM_EMAIL
                recipient_list=[email],
                fail_silently=False,
            )
            
            return Response({
                'message': 'User created successfully. Email sent. Redirecting to student card...',
                'user': serializer.data,
                'tokens': token
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


## Token Generation 
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


## Protected Route
class ProtectedView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
  
    def get(self, request):
        return Response({"message": "You have access!"})


## Token Refresh Route
class TokenRefreshView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response({'error': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            new_access_token = str(token.access_token)
            return Response({'access': new_access_token}, status=status.HTTP_200_OK)
        except TokenError as e:
            return Response({'error': 'Invalid or expired refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)
        