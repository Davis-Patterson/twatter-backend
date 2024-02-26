import re
from django.contrib.auth import get_user_model

def find_mentions(text):
    pattern = r'@(\w+)'
    usernames = re.findall(pattern, text)
    return set(usernames)