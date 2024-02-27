from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from api.views import LoginView, LogoutView, UserViewSet, PostViewSet, CommentViewSet, MessageViewSet, FollowViewSet, PokeViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'posts', PostViewSet)
router.register(r'comments', CommentViewSet)
router.register(r'messages', MessageViewSet)
router.register(r'follow', FollowViewSet, basename='follow')
router.register(r'pokes', PokeViewSet, basename='pokes')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('', include(router.urls)),
    path('users/update/', UserViewSet.as_view({'patch': 'update_profile'}), name='user-update-profile'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
