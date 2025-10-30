from django.contrib import admin
from .models import Project, Deployment, Tag, ProjectTag, SocialAccount

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ['name', 'owner', 'status', 'exposed_port', 'is_public', 'created_at']
    list_filter = ['status', 'is_public', 'created_at']
    search_fields = ['name', 'github_repo_url', 'owner__username']
    readonly_fields = ['created_at', 'updated_at']

@admin.register(Deployment)
class DeploymentAdmin(admin.ModelAdmin):
    list_display = ['project', 'status', 'timestamp']
    list_filter = ['status', 'timestamp']
    search_fields = ['project__name', 'log']

@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug']
    search_fields = ['name', 'slug']

@admin.register(ProjectTag)
class ProjectTagAdmin(admin.ModelAdmin):
    list_display = ['project', 'tag']
    search_fields = ['project__name', 'tag__name']

@admin.register(SocialAccount)
class SocialAccountAdmin(admin.ModelAdmin):
    list_display = ['user', 'provider', 'uid']
    search_fields = ['user__username', 'provider', 'uid']