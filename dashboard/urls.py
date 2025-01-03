from django.urls import path, re_path
import re

from . import views

urlpatterns = [
    path("", views.kplogin, name="kplogin"),
    path("main", views.kpmain, name="kpmain"),
    path("logout", views.logout_view, name="logout_view"),
    path("add_domain", views.add_domain, name="add_domain"),
    path("save_domain/<str:domain>", views.save_domain, name="save_domain"),
    path("view_domain/<str:domain>", views.view_domain, name="view_domain"),
    path("volumesnapshots/<str:domain>", views.volumesnapshots, name="volumesnapshots"),
    path("restore_volumesnapshot/<str:domain>/<str:volumesnapshot>", views.restore_volumesnapshot, name="restore_volumesnapshot"),
    path("start_backup/<str:domain>", views.start_backup, name="start_backup"),
    path("settings", views.settings, name="settings"),
    path("delete_domain/<str:domain>", views.delete_domain, name="delete_domain"),
    path("startstop_domain/<str:domain>/<str:action>", views.startstop_domain, name="startstop_domain"),
]
