# Generated by Django 5.0.2 on 2024-02-23 16:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_post_is_private_user_is_private_followrequest'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='link',
            field=models.URLField(blank=True, help_text='Link to a website.', null=True),
        ),
    ]