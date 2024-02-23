from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

User = get_user_model()

class PostTests(APITestCase):
    """
    Test suite for the Post model viewset.
    
    This class contains tests that verify the functionality of the endpoints associated
    with the Post model, including creating, retrieving, updating, and deleting posts,
    as well as authorization checks and interaction with the Comment and Message models.
    """

    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.create_post_url = reverse('post-list')

    def test_create_post(self):
        """
        Ensure we can create a new post object.
        """
        self.client.login(username='testuser', password='testpassword')
        data = {'content': 'Test Post'}
        response = self.client.post(self.create_post_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['content'], 'Test Post')
        self.assertEqual(response.data['author'], self.user.id)

    def test_get_posts(self):
        """
        Ensure we can retrieve a list of posts.
        """
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(self.create_post_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_post(self):
        """
        Ensure we can update an existing post object.
        """
        self.client.login(username='testuser', password='testpassword')
        response = self.client.post(self.create_post_url, {'content': 'Initial Post'}, format='json')
        post_id = response.data['id']
        update_data = {'content': 'Updated Post'}
        response = self.client.put(reverse('post-detail', args=[post_id]), update_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['content'], 'Updated Post')

    def test_delete_post(self):
        """
        Ensure we can delete a post object.
        """
        self.client.login(username='testuser', password='testpassword')
        response = self.client.post(self.create_post_url, {'content': 'Post to be deleted'}, format='json')
        post_id = response.data['id']
        response = self.client.delete(reverse('post-detail', args=[post_id]), format='json')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        response = self.client.get(reverse('post-detail', args=[post_id]), format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_create_comment(self):
        """
        Ensure we can create a new comment for a post.
        """
        self.client.login(username='testuser', password='testpassword')
        data = {'content': 'Test Comment', 'post': 1}
        response = self.client.post(reverse('comment-list'), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['content'], 'Test Comment')

    def test_send_message(self):
        """
        Ensure we can create and send a new message to another user.
        """
        recipient = User.objects.create_user(username='recipient', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'content': 'Hello', 'recipient': recipient.id}
        response = self.client.post(reverse('message-list'), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['content'], 'Hello')
        self.assertEqual(response.data['recipient'], recipient.id)

    def test_get_messages(self):
        """
        Ensure we can retrieve a list of messages for the logged in user.
        """
        self.client.login(username='recipient', password='testpassword')
        response = self.client.get(reverse('message-list'), format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('Hello' in [message['content'] for message in response.data])

    def test_unauthorized_access(self):
        """
        Ensure that unauthorized access to create a post is not permitted.
        """
        data = {'content': 'Unauthorized Post'}
        response = self.client.post(self.create_post_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
