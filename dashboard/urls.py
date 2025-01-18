from django.urls import path, re_path
import re

from . import views

urlpatterns = [
    path("", views.kplogin, name="kplogin"),
    path("main", views.kpmain, name="kpmain"),
    path("logout", views.logout_view, name="logout_view"),
    path('blocked-objects/', views.blocked_objects, name='blocked_objects'),
    path("add_domain", views.add_domain, name="add_domain"),
    path("save_domain/<str:domain>", views.save_domain, name="save_domain"),
    path("view_domain/<str:domain>", views.view_domain, name="view_domain"),
    path("volumesnapshots/<str:domain>", views.volumesnapshots, name="volumesnapshots"),
    path("restore_volumesnapshot/<str:domain>/<str:volumesnapshot>", views.restore_volumesnapshot, name="restore_volumesnapshot"),
    path("start_backup/<str:domain>", views.start_backup, name="start_backup"),
    path("settings", views.settings, name="settings"),
    path("livetraffic", views.livetraffic, name="livetraffic"),
    path("delete_domain/<str:domain>", views.delete_domain, name="delete_domain"),
    path("startstop_domain/<str:domain>/<str:action>", views.startstop_domain, name="startstop_domain"),
    path("block_entry/<str:vhost>/<str:x_forwarded_for>/<path:path>/",views.block_entry,name='block_entry'),
    path('pods-status/', views.get_pods_status, name='pods_status'),
    path('tokens/add/', views.add_api_token, name='add_api_token'),
    path('tokens/list/', views.list_api_tokens, name='list_api_tokens'),
    path('zones/create/', views.create_zone, name='create_zone'),
    path('zones/list/', views.zones_list, name='zones_list'),
    path('records/create/', views.create_dns_record, name='create_dns_record'),
    path("zones/<int:zone_id>/records/", views.list_dns_records, name="list_dns_records"),
]
