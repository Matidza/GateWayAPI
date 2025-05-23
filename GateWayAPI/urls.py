
from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from . import settings
from django.views.generic import RedirectView  # 👈 import this
#from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshSlidingView


urlpatterns = [
    path('', RedirectView.as_view(url='/api/auth/', permanent=False)),
    path('admin/', admin.site.urls),
    path('api/auth/', include('LoginRegister.urls')),
    #path('api/auth/', include('rest_framework.urls'))

    
]  
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
