from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.user_login, name='user_login'),
    path('logout/', views.user_logout, name='user_logout'),
    path('signup/', views.signup, name='signup'),

    path('dashboard/', views.dashboard, name='dashboard'),
    path('projects/', views.project_list, name='project_list'),
    path('projects/<int:project_id>/', views.project_detail, name='project_detail'),
    path('projects/create/', views.create_project, name='create_project'),
    path('projects/<int:project_id>/deploy/', views.deploy_project, name='deploy_project'),
    path('deployments/<int:deployment_id>/', views.deployment_detail, name='deployment_detail'),
    path('api/deployments/<int:deployment_id>/log/', views.deployment_log_api, name='deployment_log_api'),
    path('projects/<int:project_id>/delete/', views.delete_project, name='delete_project'),
    path('projects/<int:project_id>/stop/', views.stop_project, name='stop_project'),

    path('explore/', views.explore_projects, name='explore_projects'),

    path('projects/tags/add/', views.add_project_tag, name='add_project_tag'),
    path('projects/tags/remove/', views.remove_project_tag, name='remove_project_tag'),

    path('profile/', views.profile, name='profile'),
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),

    path('u/<str:username>/', views.public_profile, name='public_profile'),

    path('github/login/', views.github_login, name='github_login'),
    path('github/callback/', views.github_callback, name='github_callback'),
    path('github/disconnect/', views.github_disconnect, name='github_disconnect'),

    path('webhook/github/<int:project_id>/', views.github_webhook, name='github_webhook'),

    path('health/', views.health_check, name='health_check'),
]