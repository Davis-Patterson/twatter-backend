from django.db.models.signals import post_save, post_delete, m2m_changed
from django.dispatch import receiver
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from .models import Post, Comment, User, Notification
from .utils import find_mentions

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

@receiver(m2m_changed, sender=Post.likers.through)
def post_liked(sender, instance, action, pk_set, **kwargs):
    if action == "post_add":
        for pk in pk_set:
            Notification.objects.create(
                recipient=instance.author,
                sender=User.objects.get(pk=pk),
                notification_type='like_post',
                post=instance
            )

@receiver(post_save, sender=Post)
def notify_tagged_users_in_post(sender, instance, created, **kwargs):
    if created:
        mentioned_usernames = find_mentions(instance.content)
        tagged = []
        for username in mentioned_usernames:
            try:
                user = User.objects.get(username=username)
                tagged.append(user)
                Notification.objects.create(
                    recipient=user,
                    sender=instance.author,
                    notification_type='tag',
                    post=instance
                )
            except User.DoesNotExist:
                continue
        instance.tagged.set(tagged)

@receiver(post_save, sender=Comment)
def notify_tagged_users_in_comment(sender, instance, created, **kwargs):
    if created:
        mentioned_usernames = find_mentions(instance.content)
        tagged = []
        for username in mentioned_usernames:
            try:
                user = User.objects.get(username=username)
                tagged.append(user)
                Notification.objects.create(
                    recipient=user,
                    sender=instance.author,
                    notification_type='tag',
                    comment=instance
                )
            except User.DoesNotExist:
                continue
        instance.tagged.set(tagged)
