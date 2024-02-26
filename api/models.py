from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import m2m_changed
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

class User(AbstractUser):
    private = models.BooleanField(default=False)
    online = models.BooleanField(default=False)
    display_name = models.CharField(max_length=20, blank=True)
    birthday = models.DateField(null=True, blank=True)
    picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    banner = models.ImageField(upload_to='profile_banner/', null=True, blank=True)
    bio = models.CharField(max_length=200, blank=True)
    link = models.URLField(max_length=200, blank=True, null=True, help_text="Link to a website.")
    following = models.ManyToManyField('self', symmetrical=False, related_name='followers', blank=True)
    last_online = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    @property
    def follower_count(self):
        return self.followers.count()

    @property
    def following_count(self):
        return self.following.count()

class FollowRequest(models.Model):
    from_user = models.ForeignKey(User, related_name='sent_follow_requests', on_delete=models.CASCADE)
    to_user = models.ForeignKey(User, related_name='received_follow_requests', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)

    class Meta:
        unique_together = ('from_user', 'to_user')

    def __str__(self):
        return f"{self.from_user} -> {self.to_user}"

class Post(models.Model): 
    private = models.BooleanField(default=False)
    content = models.TextField(blank=True, null=True, max_length=500)
    image = models.ImageField(upload_to='post_images/', blank=True, null=True)
    video = models.FileField(upload_to='post_videos/', blank=True, null=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    created_at = models.DateTimeField(auto_now_add=True)
    tagged = models.ManyToManyField(User, related_name='tagged_in_posts', blank=True)
    likers = models.ManyToManyField(User, related_name='liked_posts', blank=True)
    like_count = models.IntegerField(default=0)
    comment_count = models.IntegerField(default=0)

    def clean(self):
        if not self.content and not self.image and not self.video:
            raise ValidationError('Posts must have at least some content (text, image, or video).')

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    content = models.CharField(max_length=300)
    created_at = models.DateTimeField(auto_now_add=True)
    tagged = models.ManyToManyField(User, related_name='tagged_in_comments', blank=True)
    likers = models.ManyToManyField(User, related_name='liked_comments')
    like_count = models.IntegerField(default=0)

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='message_images/', blank=True, null=True)
    video = models.FileField(upload_to='message_videos/', blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)

    def clean(self):
        if not self.content and not self.image and not self.video:
            raise ValidationError('Comments must have at least some content (text, image, or video).')

class Notification(models.Model):
    TYPE_CHOICES = (
        ('tag', 'Tag'),
        ('like_post', 'Like on Post'),
        ('like_comment', 'Like on Comment'),
        ('follow', 'Follow'),
        ('follow_request', 'Follow Request'),
    )
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
    notification_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    date = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    post = models.ForeignKey(Post, on_delete=models.SET_NULL, null=True, blank=True)
    comment = models.ForeignKey(Comment, on_delete=models.SET_NULL, null=True, blank=True)
    follow_request = models.ForeignKey(FollowRequest, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-date']

    def __str__(self):
        return f"{self.sender} -> {self.recipient}: {self.notification_type}"
