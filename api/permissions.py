from rest_framework import permissions
from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsAuthorOrAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow the author of a post or an admin to delete it.
    """

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        if view.action == 'destroy':
            return obj.author == request.user or request.user.is_staff
        return True

class IsOwnerOrReadOnly(BasePermission):
    """
    Custom permission to only allow owners of an object to edit or delete it.
    """

    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True

        return obj.author == request.user

class IsOwnerOrPostAuthorOrReadOnly(BasePermission):
    """
    Custom permission to only allow owners of an object or the author of the post
    the object is related to, to edit or delete it.
    """

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        if obj.author == request.user:
            return True

        if obj.post.author == request.user:
            return True

        return request.user.is_staff

class CanComment(BasePermission):
    """
    Permission to only allow commenting on a post if it's public,
    or if it's private and the user is following the author.
    """

    def has_object_permission(self, request, view, obj):
        if obj.is_private:
            return obj.author.followers.filter(id=request.user.id).exists()
        else:
            return True
