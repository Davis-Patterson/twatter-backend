from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import FollowRequest, User, Post, Comment, Message
from rest_framework.authtoken.models import Token
from django.contrib.auth.hashers import make_password

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    follower_count = serializers.IntegerField(read_only=True)
    following_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'email', 'display_name', 'birthday', 'bio', 'link', 'picture', 'banner', 'follower_count', 'following_count', 'following', 'is_private')
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

class FollowRequestSerializer(serializers.ModelSerializer):
    from_user = serializers.SlugRelatedField(slug_field='username', read_only=True)
    to_user = serializers.SlugRelatedField(slug_field='username', read_only=True)
    
    class Meta:
        model = FollowRequest
        fields = ['id', 'from_user', 'to_user', 'created_at', 'is_approved']

class CommentSerializer(serializers.ModelSerializer):
    author_id = serializers.ReadOnlyField(source='author.id')
    author = serializers.ReadOnlyField(source='author.username')

    class Meta:
        model = Comment
        fields = ['id', 'post', 'author_id', 'author', 'content', 'created_at', 'likers', 'like_count']

class PostSerializer(serializers.ModelSerializer):
    author_id = serializers.ReadOnlyField(source='author.id')
    author = serializers.ReadOnlyField(source='author.username')
    comments = CommentSerializer(many=True, read_only=True)

    class Meta:
        model = Post
        fields = ['is_private', 'id', 'author_id', 'author', 'content', 'image', 'video', 'created_at', 'likers', 'like_count', 'comment_count', 'comments']

class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.ReadOnlyField(source='sender.id')
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
