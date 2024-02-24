from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import FollowRequest, User, Post, Comment, Message
from rest_framework.authtoken.models import Token
from django.contrib.auth.hashers import make_password

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    follower_count = serializers.IntegerField(read_only=True)
    following_count = serializers.IntegerField(read_only=True)
    followers = serializers.SerializerMethodField()
    following = serializers.SlugRelatedField(
        many=True, 
        slug_field='username', 
        queryset=User.objects.all(), 
        required=False
    )

    class Meta:
        model = User
        fields = ( 'id', 'private', 'online', 'username', 'password', 'email', 'display_name', 'birthday', 'bio', 'link', 'picture', 'banner', 'follower_count', 'followers', 'following_count', 'following', 'last_online', 'created')
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data.get('password'))
        return super(UserSerializer, self).create(validated_data)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            if attr in ['picture', 'banner']:
                file_field = getattr(instance, attr)
                if file_field and value:
                    file_field.delete(save=False)
            setattr(instance, attr, value)
        instance.save()
        return instance
    
    def get_followers(self, obj):
        return [follower.username for follower in obj.followers.all()]

class FollowRequestSerializer(serializers.ModelSerializer):
    from_user = serializers.SlugRelatedField(slug_field='username', read_only=True)
    to_user = serializers.SlugRelatedField(slug_field='username', read_only=True)
    
    class Meta:
        model = FollowRequest
        fields = ['id', 'from_user', 'to_user', 'created_at', 'is_approved']

class CommentSerializer(serializers.ModelSerializer):
    author_id = serializers.ReadOnlyField(source='author.id')
    author = serializers.ReadOnlyField(source='author.username')
    likers = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='username'
    )

    class Meta:
        model = Comment
        fields = ['id', 'post', 'author_id', 'author', 'content', 'created_at', 'likers', 'like_count']

class PostSerializer(serializers.ModelSerializer):
    author_id = serializers.ReadOnlyField(source='author.id')
    author = serializers.ReadOnlyField(source='author.username')
    likers = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='username'
    )
    comments = CommentSerializer(many=True, read_only=True)

    class Meta:
        model = Post
        fields = ['private', 'id', 'author_id', 'author', 'content', 'image', 'video', 'created_at', 'likers', 'like_count', 'comment_count', 'comments']

class MessageSerializer(serializers.ModelSerializer):
    sender_id = serializers.ReadOnlyField(source='sender.id')
    sender = serializers.SlugRelatedField(
        read_only=True,
        slug_field='username'
    )
    recipient = serializers.SlugRelatedField(
        slug_field='username',
        queryset=User.objects.all(),
        write_only=True
    )

    class Meta:
        model = Message
        fields = '__all__'
        extra_kwargs = {
            'recipient': {'write_only': True},
        }

    def create(self, validated_data):
        recipient_username = validated_data.pop('recipient')
        recipient = User.objects.get(username=recipient_username)
        message = Message.objects.create(recipient=recipient, **validated_data)
        return message
