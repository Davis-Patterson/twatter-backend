from rest_framework import viewsets
from .models import Post, User, Comment, Message, FollowRequest, Notification, Poke
from .serializers import PostSerializer, UserSerializer, UserPublicSerializer, CommentSerializer, MessageSerializer, FollowRequestSerializer, NotificationSerializer, PokeSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.authentication import TokenAuthentication
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import viewsets, status
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
from django.utils.timezone import now
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
            'follow_status': None,
            'picture': user.picture.url if user.picture else None,
            'banner': user.banner.url if user.banner else None,
            'bio': user.bio,
            'link': user.link,
            'follower_count': user.followers.count(),
            'following_count': user.following.count()
        }

        if request.user == user:
            public_data['follow_status'] = 'self'
        elif request.user.is_authenticated:
            following = user.followers.filter(username=request.user.username).exists()
            followed_back = request.user.followers.filter(username=user.username).exists()

            if following and followed_back:
                public_data['follow_status'] = 'mutual'
            elif following:
                public_data['follow_status'] = 'following'
            elif followed_back:
                public_data['follow_status'] = 'follow_back'

            follow_request = FollowRequest.objects.filter(from_user=request.user, to_user=user).first()
            if follow_request:
                if follow_request.status == FollowRequest.RequestStatus.APPROVED:
                    public_data['follow_status'] = 'following'
                elif follow_request.status == FollowRequest.RequestStatus.PENDING:
                    public_data['follow_status'] = 'pending'

        return Response(public_data)

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

    @action(detail=False, methods=['get'], url_path='check-username', url_name='check_username')
    def check_username(self, request, *args, **kwargs):
        """Endpoint to check availability of usernames"""
        username_query = request.query_params.get('username', None)

        if username_query is None:
            return Response({'error': 'No username provided'}, status=status.HTTP_400_BAD_REQUEST)

        if request.user.is_authenticated:
            is_available = not User.objects.filter(Q(username__iexact=username_query) & ~Q(pk=request.user.pk)).exists()
        else:
            is_available = not User.objects.filter(username__iexact=username_query).exists()

        return Response({'is_available': is_available})

    @action(detail=False, methods=['get'], url_path='check-auth')
    def check_auth_status(self, request):
        """
        Endpoint to check the user's authentication status.
        """
        if request.user.is_authenticated:
            return Response({'status': 'Authenticated', 'user': request.user.username}, status=status.HTTP_200_OK)
        else:
            return Response({'status': 'Unauthenticated'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], url_path='followers')
    def user_followers(self, request, username=None):
        """Endpoint to retrieve followers list"""
        user = self.get_object()
        if (user.private and user != request.user and 
                not user.followers.filter(username=request.user.username).exists()):
            return Response({"detail": "You do not have permission to view the followers of this user."}, 
                            status=status.HTTP_403_FORBIDDEN)

        followers = user.followers.all()
        serializer = UserPublicSerializer(followers, many=True, context={'request': request})
        data = self.reorder_users(serializer.data, request.user)
        return Response(data)

    @action(detail=True, methods=['get'], url_path='followings')
    def user_followings(self, request, username=None):
        """Endpoint to retrieve followings list"""
        user = self.get_object()
        if (user.private and user != request.user and 
                not user.following.filter(username=request.user.username).exists()):
            return Response({"detail": "You do not have permission to view the followings of this user."}, 
                            status=status.HTTP_403_FORBIDDEN)

        followings = user.following.all()
        serializer = UserPublicSerializer(followings, many=True, context={'request': request})
        data = self.reorder_users(serializer.data, request.user)
        return Response(data)

    def reorder_users(self, users_data, current_user):
        """Reorder users to have the current user at the top if they are in the list."""
        current_user_data = None
        reordered_data = []
        for user_data in users_data:
            if user_data['username'] == current_user.username:
                current_user_data = user_data
            else:
                reordered_data.append(user_data)
        if current_user_data:
            reordered_data.insert(0, current_user_data)
        return reordered_data

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
            return Response({"detail": "You are already following this user."}, status=status.HTTP_400_BAD_REQUEST)
        
        existing_request = FollowRequest.objects.filter(
            from_user=request.user, to_user=target_user
        ).exclude(
            status=FollowRequest.RequestStatus.DECLINED
        ).exclude(
            status=FollowRequest.RequestStatus.CANCELLED
        ).first()
        
        if existing_request:
            if existing_request.status == FollowRequest.RequestStatus.PENDING:
                return Response({"detail": "Follow request already sent."}, status=status.HTTP_409_CONFLICT)
            elif existing_request.status == FollowRequest.RequestStatus.APPROVED:
                return Response({"detail": "You are already following this user."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not existing_request or existing_request.status in [FollowRequest.RequestStatus.DECLINED, FollowRequest.RequestStatus.CANCELLED]:
            if target_user.private:
                FollowRequest.objects.create(from_user=request.user, to_user=target_user, status=FollowRequest.RequestStatus.PENDING)
                return Response({"detail": "Follow request sent."}, status=status.HTTP_202_ACCEPTED)
            else:
                request.user.following.add(target_user)
                return Response({"detail": "You are now following this user."}, status=status.HTTP_200_OK)
        
        return Response({"detail": "Unable to send follow request."}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'], url_path='detail')
    def follow_request_detail(self, request, pk=None):
        """
        Retrieve a single follow request.
        """
        follow_request = get_object_or_404(FollowRequest, id=pk, to_user=request.user)
        serializer = FollowRequestSerializer(follow_request)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='approve')
    def approve_follow_request(self, request, pk=None):
        follow_request = get_object_or_404(FollowRequest, id=pk, to_user=request.user, status=FollowRequest.RequestStatus.PENDING)
        follow_request.status = FollowRequest.RequestStatus.APPROVED
        follow_request.save()
        follow_request.to_user.followers.add(follow_request.from_user)
        return Response({"detail": "Follow request approved."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='reject')
    def reject_follow_request(self, request, pk=None):
        follow_request = get_object_or_404(FollowRequest, id=pk, to_user=request.user)
        follow_request.status = FollowRequest.RequestStatus.DECLINED
        follow_request.save()
        return Response({"detail": "Follow request rejected."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='pending')
    def pending_follow_requests(self, request):
        pending_requests = FollowRequest.objects.filter(to_user=request.user, status=FollowRequest.RequestStatus.PENDING)
        serializer = FollowRequestSerializer(pending_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='all')
    def all_follow_requests(self, request):
        all_requests = FollowRequest.objects.filter(to_user=request.user)
        serializer = FollowRequestSerializer(all_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='unfollow')
    def unfollow_user(self, request, pk=None):
        """Allows a user to unfollow another user by username."""
        target_user = get_object_or_404(User, username=pk)
        user_following = request.user.following

        if not user_following.filter(pk=target_user.pk).exists():
            return Response({"detail": "You are not following this user."}, status=status.HTTP_400_BAD_REQUEST)

        user_following.remove(target_user)

        FollowRequest.objects.filter(
            from_user=request.user,
            to_user=target_user,
            status=FollowRequest.RequestStatus.PENDING
        ).delete()

        FollowRequest.objects.filter(
            from_user=request.user,
            to_user=target_user,
            status=FollowRequest.RequestStatus.APPROVED
        ).update(status=FollowRequest.RequestStatus.CANCELLED)

        return Response({"detail": "You have unfollowed the user."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['delete'], url_path='delete')
    def delete_follow_request(self, request, pk=None):
        """Deletes a follow request."""
        follow_request = get_object_or_404(FollowRequest, pk=pk, from_user=request.user)

        follow_request.delete()

        return Response({"detail": "Follow request deleted."}, status=status.HTTP_204_NO_CONTENT)

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

class PokeViewSet(viewsets.ViewSet):
    """
    A viewset for viewing and editing user pokes.
    """
    permission_classes = [IsAuthenticated]

    def list(self, request):
        """
        Optionally restricts the returned pokes to a given user,
        by filtering against a `username` query parameter in the URL.
        """
        queryset = Poke.objects.filter(recipient=request.user, read=False)
        serializer = PokeSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='send')
    def send_poke(self, request, pk=None):
        """
        Send a poke to a user.
        """
        sender = request.user
        recipient = get_object_or_404(User, pk=pk)

        if not recipient.can_poke:
            return Response({"detail": "User cannot be poked."}, status=status.HTTP_403_FORBIDDEN)

        if sender == recipient:
            return Response({"detail": "You cannot poke yourself."}, status=status.HTTP_400_BAD_REQUEST)

        poke = Poke.objects.create(sender=sender, recipient=recipient)

        Notification.objects.create(
            recipient=recipient,
            sender=sender,
            notification_type='poke',
            date=now(),
            poke=poke,
        )

        return Response({"detail": f"You have poked {recipient.username}!"}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='mark-as-read')
    def mark_as_read(self, request, pk=None):
        """
        Mark a poke as read.
        """
        poke = get_object_or_404(Poke, pk=pk, recipient=request.user)
        poke.read = True
        poke.save()
        return Response({"detail": "Poke marked as read."}, status=status.HTTP_200_OK)

class NotificationViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        queryset = Notification.objects.filter(recipient=request.user).order_by('-date')
        serializer = NotificationSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['patch'], url_path='mark-read')
    def mark_read(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

        notification_ids = request.data.get('notification_ids', [])
        if not notification_ids:
            return Response({'error': 'No notification IDs provided'}, status=status.HTTP_400_BAD_REQUEST)

        notifications_to_mark = Notification.objects.filter(recipient=user, id__in=notification_ids)
        notifications_to_mark.update(read=True)
        return Response({'detail': 'Notifications marked as read'}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['patch'], url_path='mark-all-read')
    def mark_all_read(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

        Notification.objects.filter(recipient=user).update(read=True)

        return Response({'detail': 'All notifications marked as read'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['delete'], url_path='delete')
    def delete(self, request, pk=None):
        """
        Delete a notification for a user.
        """
        user = request.user
        if not user.is_authenticated:
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

        notification = get_object_or_404(Notification, pk=pk, recipient=user)
        notification.delete()
        return Response({"detail": "Notification deleted."}, status=status.HTTP_204_NO_CONTENT)
    