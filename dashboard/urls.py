from django.urls import path, re_path
import re

from . import views

urlpatterns = [
    path("", views.kplogin, name="kplogin"),
    path("main", views.kpmain, name="kpmain"),
    path("logout", views.logout_view, name="logout_view"),
    path("add_domain", views.add_domain, name="add_domain"),
    path("view_domain/<str:domain>", views.view_domain, name="view_domain"),
    path("volumesnapshots/<str:domain>", views.volumesnapshots, name="volumesnapshots"),
    path("restore_volumesnapshot/<str:volumesnapshot>", views.restore_volumesnapshot, name="restore_volumesnapshot"),
    path("settings", views.settings, name="settings"),
    path("delete_domain/<str:domain>", views.delete_domain, name="delete_domain"),
]
