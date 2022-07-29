from admin_honeypot import views
from django.urls import path, re_path

app_name = 'admin_honeypot'

urlpatterns = [
    path('login/', views.AdminHoneypot.as_view(), name='login'),
    path('login2/', views.AdminHoneypotSQLi.as_view(), name='login_sqli'),
    path('hashcash_metadata/', views.hashcash_metadata, name='hashcash_metadata'),
    path('read_files/', views.PathTraversal.as_view(), name='path_traversal'),
    re_path(r'^.*$', views.AdminHoneypot.as_view(), name='index'),
]

handler404 = 'admin_honeypot.views.handler404'
