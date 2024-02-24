from rest_framework import viewsets
from .models import Post, User, Comment, Message, FollowRequest
from .serializers import PostSerializer, UserSerializer, CommentSerializer, MessageSerializer, FollowRequestSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.authentication import TokenAuthentication
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import action
from rest_framework import status
from rest_framework.response import Response
from .permissions import IsAuthorOrAdminOrReadOnly, CanComment, IsOwnerOrPostAuthorOrReadOnly
from rest_framework.exceptions import PermissionDenied
from django.db.models import Q, OuterRef, Max
from django.shortcuts import get_object_or_404
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.contrib.auth import authenticate
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from django.views import View
from django.utils import timezone
from django.http import JsonResponse
import json

class LoginView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            token, _ = Token.objects.get_or_create(user=user)
            response = JsonResponse({"detail": "Successfully logged in."}, safe=False)
            response.set_cookie(
                'auth_token',
                token.key,
                httponly=True,
                secure=True,
                samesite='none'
            )
            return response
        else:
            return JsonResponse({"detail": "Invalid credentials"}, status=401)

class LogoutView(View):
    def post(self, request, *args, **kwargs):
        response = JsonResponse({"detail": "Successfully logged out."})
        response.delete_cookie('auth_token')
        return response

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'username'
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get_permissions(self):
        if self.action == 'retrieve':
            permission_classes = [AllowAny]
        elif self.action in ['follow', 'unfollow', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [AllowAny]
        return [permission() for permission in permission_classes]

    @action(detail=False, methods=['get'], url_path='profile')
    def user_profile(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        user = self.get_object()
        public_data = {
            'private': user.private,
            'username': user.username,
            'display_name': user.display_name,
            'picture': user.picture.url if user.picture else None,
            'banner': user.banner.url if user.banner else None,
            'bio': user.bio,
            'link': user.link,
            'follower_count': user.followers.count(),
            'following_count': user.following.count()
        }
        if not user.private or user.followers.filter(username=request.user.username).exists():
            public_data['followers'] = UserSerializer(user.followers.all(), many=True).data
            public_data['followings'] = UserSerializer(user.following.all(), many=True).data
            
            user_posts = Post.objects.filter(author=user).order_by('-created_at')
            public_data['posts'] = PostSerializer(user_posts, many=True).data
        
        return Response(public_data)

    @action(detail=True, methods=['get'], url_path='followers')
    def followers(self, request, username=None):
        user = get_object_or_404(User, username=username)
        if user.private and not user.followers.filter(username=request.user.username).exists():
            return Response({"detail": "You do not have permission to view the followers of this user."}, 
                            status=status.HTTP_403_FORBIDDEN)

        followers = user.followers.all()
        serializer = UserSerializer(followers, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['patch'], url_path='update', url_name='update_profile')
    def update_profile(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        if 'username' in request.data:
            new_username = request.data['username']
            if User.objects.filter(username=new_username).exclude(pk=user.pk).exists():
                return Response({'username': ['This username is already taken.']}, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()

        if getattr(user, '_prefetched_objects_cache', None):
            user._prefetched_objects_cache = {}

        return Response(serializer.data)

    @action(detail=False, methods=['post'], url_path='online-status')
    def set_online_status(self, request):
        user = request.user
        online_status = request.data.get('online', None)

        if online_status is not None:
            user.online = online_status
            if not online_status:
                user.last_online = timezone.now()
            user.save(update_fields=['online', 'last_online'])

            return Response({
                'online': user.online,
                'last_online': user.last_online.isoformat() if user.last_online else None
            })

        return Response({'error': 'Online status not provided'}, status=status.HTTP_400_BAD_REQUEST)

class FollowViewSet(viewsets.ViewSet):
    """
    A viewset for viewing and editing user follows.
    """
    serializer_class = UserSerializer
    queryset = User.objects.all()

    def get_permissions(self):
        """
        Instantiate and return the list of permissions that this view requires.
        """
        if self.action in ['list_following', 'toggle_follow']:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [AllowAny]
        return [permission() for permission in permission_classes]

    @action(detail=False, methods=['get'], url_path='following')
    def list_following(self, request):
        """List all users that the current user is following."""
        user = request.user
        following_users = user.following.all()
        serializer = self.get_serializer(following_users, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='request-follow')
    def request_follow(self, request, pk=None):
        target_user = get_object_or_404(User, username=pk)
        if request.user == target_user:
            return Response({"detail": "You cannot follow yourself."}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.following.filter(username=pk).exists():
            request.user.following.remove(target_user)
            return Response({"detail": "You have unfollowed this user."}, status=status.HTTP_200_OK)
        
        if target_user.private:
            existing_request = FollowRequest.objects.filter(from_user=request.user, to_user=target_user).first()
            if existing_request:
                return Response({"detail": "Follow request already sent or you are already following this user."}, status=status.HTTP_409_CONFLICT)
            
            FollowRequest.objects.create(from_user=request.user, to_user=target_user)
            return Response({"detail": "Follow request sent."}, status=status.HTTP_202_ACCEPTED)
        else:
            request.user.following.add(target_user)
            return Response({"detail": "You are now following this user."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='approve-follow-request')
    def approve_follow_request(self, request, pk=None):
        follow_request = get_object_or_404(FollowRequest, id=pk, to_user=request.user, is_approved=False)
        follow_request.is_approved = True
        follow_request.save()
        follow_request.to_user.followers.add(follow_request.from_user)
        return Response({"detail": "Follow request approved."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='reject-follow-request')
    def reject_follow_request(self, request, pk=None):
        follow_request = get_object_or_404(FollowRequest, id=pk, to_user=request.user)
        follow_request.delete()
        return Response({"detail": "Follow request rejected."}, status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=False, methods=['get'], url_path='pending-follow-requests')
    def pending_follow_requests(self, request):
        pending_requests = FollowRequest.objects.filter(to_user=request.user, is_approved=False)
        serializer = FollowRequestSerializer(pending_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticatedOrReadOnly, IsAuthorOrAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['author__username', 'author__id']

    @action(detail=True, methods=['delete'])
    def delete_post(self, request, pk=None):
        post = self.get_object()
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['get'], url_path='by-user/(?P<username>[^/.]+)')
    def user_posts(self, request, username=None):
        target_user = get_object_or_404(User, username=username)
        if target_user.private and target_user != request.user and not request.user.following.filter(username=username).exists():
            return Response({"detail": "This user's posts are private."}, status=status.HTTP_403_FORBIDDEN)

        queryset = Post.objects.filter(author=target_user).order_by('-created_at')
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'], url_path='feed')
    def user_feed(self, request):
        user = request.user
        following_users = user.following.all()

        queryset = Post.objects.filter(
            Q(author__in=following_users, author__private=False) | 
            Q(author=user)
        ).distinct().order_by('-created_at')
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def like_post(self, request, pk=None):
        post = self.get_object()
        if post.private and not post.author.followers.filter(id=request.user.id).exists():
            return Response({"detail": "You cannot like a private post of a user you're not following."}, status=status.HTTP_403_FORBIDDEN)
        
        if request.user in post.likers.all():
            post.likers.remove(request.user)
            action_detail = "Post unliked successfully."
        else:
            post.likers.add(request.user)
            action_detail = "Post liked successfully."
        
        post.save()
        return Response({"detail": action_detail}, status=status.HTTP_200_OK)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        data['author'] = request.user.id
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()

        if instance.author != request.user:
            raise PermissionDenied("You do not have permission to edit this post.")

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='add-comment', permission_classes=[CanComment])
    def add_comment(self, request, pk=None):
        post = self.get_object()
        comment_content = request.data.get('content')
        if not comment_content:
            return Response({'detail': 'Content for the comment is required.'}, status=status.HTTP_400_BAD_REQUEST)

        Comment.objects.create(post=post, author=request.user, content=comment_content)
        return Response({'detail': 'Comment added successfully.'}, status=status.HTTP_201_CREATED)

class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticatedOrReadOnly, IsOwnerOrPostAuthorOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def like_comment(self, request, pk=None):
        comment = self.get_object()
        if request.user in comment.likers.all():
            comment.likers.remove(request.user)
            action_detail = "Comment unliked successfully."
        else:
            comment.likers.add(request.user)
            action_detail = "Comment liked successfully."

        comment.save()
        return Response({"detail": action_detail}, status=status.HTTP_200_OK)

class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        recent_messages = Message.objects.filter(
            recipient=user,
            sender=OuterRef('sender')
        ).order_by('-timestamp')
        last_message_in_conversation = recent_messages.values('sender').annotate(last_id=Max('id')).values('last_id')
        queryset = Message.objects.filter(
            id__in=last_message_in_conversation
        ).order_by('sender', '-timestamp')
        return queryset

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)

    @action(detail=False, methods=['post'])
    def send_message(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save(sender=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def get_conversation(self, request):
        recipient_username = request.query_params.get('recipient')
        try:
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            return Response({"detail": "Recipient not found."}, status=status.HTTP_404_NOT_FOUND)

        messages = Message.objects.filter(
            Q(sender=request.user, recipient=recipient) | Q(sender=recipient, recipient=request.user)
        ).order_by('timestamp')

        serializer = self.get_serializer(messages, many=True)
        return Response(serializer.data)
