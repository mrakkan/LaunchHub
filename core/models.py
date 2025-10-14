from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.template.defaultfilters import slugify
from django.core.exceptions import ValidationError
import uuid
import subprocess
import os
import json
import tempfile
import shutil
import time
import urllib.request


class Tag(models.Model):
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    
    class Meta:
        db_table = 'tags'
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)


class Project(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('deploying', 'Deploying'),
        ('running', 'Running'),
        ('failed', 'Failed'),
        ('stopped', 'Stopped'),
    ]
    
    name = models.CharField(max_length=100)
    github_repo_url = models.URLField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    is_public = models.BooleanField(default=False)
    exposed_port = models.IntegerField(null=True, blank=True)
    docker_container_id = models.CharField(max_length=100, blank=True)
    docker_image_name = models.CharField(max_length=100, blank=True)
    dockerfile_path = models.CharField(max_length=200, default='Dockerfile')
    build_command = models.CharField(max_length=200, blank=True, help_text="Custom build command if needed")
    run_command = models.CharField(max_length=200, blank=True, help_text="Custom run command if needed")
    environment_variables = models.TextField(blank=True, help_text="JSON format environment variables")
    webhook_enabled = models.BooleanField(default=False)
    webhook_token = models.CharField(max_length=64, blank=True)
    webhook_branch = models.CharField(max_length=100, default='main', blank=True)
    container_port = models.IntegerField(default=80)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='projects')
    tags = models.ManyToManyField(Tag, through='ProjectTag', related_name='projects')
    
    class Meta:
        db_table = 'projects'
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name

    def clean(self):
        
        errors = {}
        
        name = (self.name or '').strip()
        if not name:
            errors['name'] = ['Project name is required']
        elif self.owner_id:
            qs = Project.objects.filter(owner_id=self.owner_id, name__iexact=name)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                errors['name'] = ['You already have a project with this name']
        
        url = (self.github_repo_url or '').strip()
        if not url:
            errors['github_repo_url'] = ['GitHub repository URL is required']
        elif not (url.startswith('https://github.com/') or url.startswith('http://github.com/')):
            errors['github_repo_url'] = ['GitHub URL must start with https://github.com/']
        else:
            parts = url.replace('https://github.com/', '').replace('http://github.com/', '').split('/')
            if len(parts) < 2 or not parts[0] or not parts[1]:
                errors['github_repo_url'] = ['Invalid GitHub repository URL format']
        
        if self.exposed_port is not None:
            try:
                port = int(self.exposed_port)
            except (TypeError, ValueError):
                errors['exposed_port'] = ['Port must be a valid integer']
            else:
                if port < 1 or port > 65535:
                    errors['exposed_port'] = ['Port must be between 1 and 65535']
                else:
                    qs = Project.objects.exclude(exposed_port__isnull=True).filter(exposed_port=port)
                    if self.pk:
                        qs = qs.exclude(pk=self.pk)
                    if qs.exists():
                        errors['exposed_port'] = ['This port is already used by another project']
        
        if self.environment_variables:
            try:
                parsed = json.loads(self.environment_variables)
                if not isinstance(parsed, dict):
                    errors['environment_variables'] = ['Environment variables must be a JSON object']
            except Exception:
                errors['environment_variables'] = ['Environment variables must be valid JSON']

        if errors:
            raise ValidationError(errors)
    
    def get_next_available_port(self):
        
        used_ports = Project.objects.exclude(exposed_port__isnull=True).values_list('exposed_port', flat=True)
        port = 3000
        while port in used_ports:
            port += 1
        return port
    
    def get_env_variables(self):
        
        try:
            return json.loads(self.environment_variables) if self.environment_variables else {}
        except json.JSONDecodeError:
            return {}
    
    def deploy_with_docker(self, deployment):
        
        try:
            self.status = 'deploying'
            self.save()
            def append_log(text):
                text = str(text)
                if deployment.log:
                    deployment.log += "\n" + text
                else:
                    deployment.log = text
                deployment.save(update_fields=['log'])

            deployment.status = 'in_progress'
            deployment.save(update_fields=['status'])
            append_log("Preparing deployment...")

            if not self.webhook_token:
                self.webhook_token = uuid.uuid4().hex
                self.save()
            if not self.exposed_port:
                self.exposed_port = self.get_next_available_port()
                self.save()

            repo_name = self.github_repo_url.split('/')[-1].replace('.git', '')
            tmp_dir = tempfile.gettempdir()
            clone_dir = os.path.join(tmp_dir, f"{repo_name}_{self.id}")
            if os.path.exists(clone_dir):
                shutil.rmtree(clone_dir, ignore_errors=True)
                if os.path.exists(clone_dir):
                    clone_dir = os.path.join(tmp_dir, f"{repo_name}_{self.id}_{uuid.uuid4().hex[:8]}")
            append_log(f"Cloning repository: {self.github_repo_url}")
            clone_result = subprocess.run(['git', 'clone', self.github_repo_url, clone_dir], capture_output=True, text=True)
            if clone_result.returncode != 0:
                append_log(clone_result.stderr.strip())
                raise Exception(f"Git clone failed")
            append_log("Repository cloned successfully")
            
            if self.build_command:
                append_log(f"Running custom build command in repo: {self.build_command}")
                try:
                    proc = subprocess.Popen(self.build_command, cwd=clone_dir, shell=True,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    for line in iter(proc.stdout.readline, ''):
                        if not line:
                            break
                        append_log(line.rstrip())
                    proc.wait()
                    if proc.returncode != 0:
                        raise Exception("Custom build command failed")
                except Exception as e:
                    append_log(str(e))
                    shutil.rmtree(clone_dir, ignore_errors=True)
                    raise

            dockerfile_path = os.path.join(clone_dir, self.dockerfile_path)
            if not os.path.exists(dockerfile_path):
                raise Exception(f"Dockerfile not found at {self.dockerfile_path}")

            image_name = f"{repo_name}_{self.id}".lower()
            self.docker_image_name = image_name
            self.save()
            build_cmd = ['docker', 'build', '-t', image_name, '-f', dockerfile_path, clone_dir]
            append_log(f"Building Docker image: {image_name}")
            try:
                proc = subprocess.Popen(build_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in iter(proc.stdout.readline, ''):
                    if not line:
                        break
                    append_log(line.rstrip())
                proc.wait()
                if proc.returncode != 0:
                    raise Exception("Docker build failed")
            except Exception as e:
                append_log(str(e))
                raise
            append_log("Docker image built successfully")

            env_vars = self.get_env_variables()

            staging_port = self.get_next_available_port()
            if staging_port == self.exposed_port:
                staging_port += 1
            staging_name = f"{repo_name}_{self.id}_staging"
            subprocess.run(['docker', 'rm', '-f', staging_name], capture_output=True)

            staging_cmd = ['docker', 'run', '-d', '-p', f"{staging_port}:80"]
            for key, value in env_vars.items():
                staging_cmd.extend(['-e', f"{key}={value}"])
            staging_cmd.extend(['--name', staging_name])
            staging_cmd.append(image_name)
            if self.run_command:
                staging_cmd.extend(self.run_command.split())
            append_log(f"Starting staging container on port {staging_port}...")
            staging_result = subprocess.run(staging_cmd, capture_output=True, text=True)
            if staging_result.returncode != 0:
                append_log(staging_result.stderr.strip())
                raise Exception(f"Docker run (staging) failed")
            staging_container_id = staging_result.stdout.strip()

            append_log("Health checking staging container...")
            healthy = False
            staging_url = f"http://localhost:{staging_port}/"
            for _ in range(30):
                try:
                    with urllib.request.urlopen(staging_url, timeout=2):
                        healthy = True
                        break
                except Exception:
                    time.sleep(2)
            if not healthy:
                subprocess.run(['docker', 'rm', '-f', staging_container_id], capture_output=True)
                append_log(f"Staging container failed health check on {staging_url}")
                raise Exception("Staging health check failed")
            append_log("Staging container is healthy")

            canonical_name = f"{repo_name}_{self.id}"
            new_name = f"{canonical_name}_new"
            old_id = (self.docker_container_id or '').strip()

            if old_id:
                subprocess.run(['docker', 'stop', old_id], capture_output=True)
                append_log("Stopped old container to free the port")

            subprocess.run(['docker', 'rm', '-f', new_name], capture_output=True)

            final_cmd = ['docker', 'run', '-d', '-p', f"{self.exposed_port}:80"]
            for key, value in env_vars.items():
                final_cmd.extend(['-e', f"{key}={value}"])
            final_cmd.extend(['--name', new_name])
            final_cmd.append(image_name)
            if self.run_command:
                final_cmd.extend(self.run_command.split())
            append_log(f"Starting new container on port {self.exposed_port}...")
            final_result = subprocess.run(final_cmd, capture_output=True, text=True)
            if final_result.returncode != 0:
                subprocess.run(['docker', 'rm', '-f', new_name], capture_output=True)
                if old_id:
                    subprocess.run(['docker', 'start', old_id], capture_output=True)
                subprocess.run(['docker', 'rm', '-f', staging_name], capture_output=True)
                append_log(final_result.stderr.strip())
                raise Exception("Docker run (final) failed")

            new_container_id = final_result.stdout.strip()
            if old_id:
                subprocess.run(['docker', 'rm', old_id], capture_output=True)
                append_log("Removed old container")
            try:
                subprocess.run(['docker', 'rename', new_name, canonical_name], capture_output=True)
            except Exception:
                subprocess.run(['docker', 'rm', '-f', canonical_name], capture_output=True)
                subprocess.run(['docker', 'rename', new_name, canonical_name], capture_output=True)
            append_log(f"Promoted new container to '{canonical_name}'")

            self.docker_container_id = new_container_id
            self.status = 'running'
            self.save()

            subprocess.run(['docker', 'rm', '-f', staging_name], capture_output=True)
            shutil.rmtree(clone_dir, ignore_errors=True)

            deployment.status = 'success'
            deployment.save(update_fields=['status'])
            append_log(f"Deployed successfully on port {self.exposed_port}")
            return True, "Deployment completed"
        except Exception as e:
            self.status = 'failed'
            self.save()
            deployment.status = 'failed'
            deployment.save(update_fields=['status'])
            append_log(f"Error: {str(e)}")
            return False, str(e)
    
    def stop_container(self):
        
        try:
            repo_name = self.github_repo_url.split('/')[-1].replace('.git', '')
            canonical_name = f"{repo_name}_{self.id}"
            staging_name = f"{repo_name}_{self.id}_staging"
            new_name = f"{canonical_name}_new"
            if self.docker_container_id:
                subprocess.run(['docker', 'rm', '-f', self.docker_container_id], capture_output=True)
            for name in [canonical_name, new_name, staging_name]:
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
            self.docker_container_id = ''
            self.status = 'stopped'
            self.save()
            return True, "Container stopped and removed successfully"
        except Exception as e:
            return False, str(e)

    def check_container_status(self):
        
        if not self.docker_container_id:
            if self.status == 'running':
                self.status = 'stopped'
                self.save()
            return False
            
        try:
            cmd = ['docker', 'inspect', '--format', '{{.State.Running}}', self.docker_container_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0 or result.stdout.strip().lower() != 'true':
                if self.status == 'running':
                    self.status = 'stopped'
                    self.docker_container_id = ''
                    self.save()
                return False
                
            if self.status != 'running':
                self.status = 'running'
                self.save()
            return True
            
        except Exception:
            if self.status == 'running':
                self.status = 'stopped'
                self.docker_container_id = ''
                self.save()
            return False
    
    def get_preview_url(self):
        
        
        is_running = self.check_container_status()
        if is_running and self.exposed_port:
            return f"http://localhost:{self.exposed_port}/"
        return ""


class ProjectTag(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'project_tags'
        unique_together = ['project', 'tag']


class Deployment(models.Model):
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('in_progress', 'In Progress'),
    ]
    
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='deployments')
    timestamp = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='in_progress')
    log = models.TextField(blank=True)
    commit_hash = models.CharField(max_length=40, blank=True)
    
    class Meta:
        db_table = 'deployments'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.project.name} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"




class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(max_length=500, blank=True)
    company = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=100, blank=True)
    website = models.URLField(blank=True)
    github_username = models.CharField(max_length=100, blank=True)
    avatar_url = models.URLField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_profiles'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Profile - {self.user.username}"
    
    def get_full_name(self):
        
        return self.user.get_full_name() or self.user.username
    
    def get_social_links(self):
        
        links = {}
        if self.github_username:
            links['github'] = f"https://github.com/{self.github_username}"
        return links


class SocialAccount(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='social_accounts')
    provider = models.CharField(max_length=50)  # e.g., 'github'
    uid = models.CharField(max_length=255)      # user id from provider
    extra_data = models.JSONField(default=dict) # arbitrary data from provider
    
    class Meta:
        db_table = 'social_accounts'
        unique_together = ['user', 'provider']
    
    def __str__(self):
        return f"{self.provider} - {self.user.username}"
