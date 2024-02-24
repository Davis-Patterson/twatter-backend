from django.db.models.signals import post_save, post_delete, m2m_changed
from django.dispatch import receiver
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from .models import Post, Comment, User

User = get_user_model()

@receiver(m2m_changed, sender=Post.likers.through)
def update_post_likes_count(sender, instance, action, **kwargs):
    if action in ["post_add", "post_remove"]:
        instance.like_count = instance.likers.count()
        instance.save()

@receiver(m2m_changed, sender=Comment.likers.through)
def update_comment_likes_count(sender, instance, action, **kwargs):
    if action in ["post_add", "post_remove"]:
        instance.like_count = instance.likers.count()
        instance.save()

@receiver(post_save, sender=User)
def create_auth_token_and_set_last_online(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
        instance.last_online = timezone.now()
        instance.save()

@receiver(post_save, sender=Comment)
def update_post_comment_count_on_add(sender, instance, created, **kwargs):
    if created:
        post = instance.post
        post.comment_count = post.comments.count()
        post.save()

@receiver(post_delete, sender=Comment)
def update_post_comment_count_on_delete(sender, instance, **kwargs):
    post = instance.post
    post.comment_count = post.comments.count()
    post.save()
