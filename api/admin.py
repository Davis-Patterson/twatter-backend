from django.contrib import admin
from .models import FollowRequest, User, Post, Comment, Message

# Register your models here.
admin.site.register(FollowRequest)
admin.site.register(User)
admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Message)
