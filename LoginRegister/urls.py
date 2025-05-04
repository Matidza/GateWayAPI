from django.urls import path
from .views import (
    DashboardView, SigninPageView, SignupPageView, ProtectedView, 
    TokenRefreshView, LogoutView,  ForgotPasswordView,
    ResetPasswordView
   )


urlpatterns = [
   path('', SigninPageView.as_view(), name='signin'),
   path('signup/', SignupPageView.as_view(), name='signup'),
   path('logout/', LogoutView.as_view(), name='logout'),
   path('dashboard/', DashboardView.as_view(), name='dashboard'),

   path('forgot_password/', ForgotPasswordView.as_view(), name='forgot_password'),
   path('reset_password/', ResetPasswordView.as_view(), name='reset_password'),

   path('protected/', ProtectedView.as_view(), name='protected'),
   path('refreshtoken/', TokenRefreshView.as_view(), name='refreshtoken'),
]
"""

"""