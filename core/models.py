from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.template.defaultfilters import slugify
from django.core.exceptions import ValidationError
from django.conf import settings
import uuid
import subprocess
import os
import json
import tempfile
import shutil
import time
import urllib.request
import urllib.error
import socket


class Tag(models.Model):
    """Model for storing project tags"""
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
    """Model for storing project information"""
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
    environment_variables = models.TextField(blank=True, help_text="Environment variables in JSON or KEY=VALUE lines")
    # webhook settings
    webhook_enabled = models.BooleanField(default=False)
    webhook_token = models.CharField(max_length=64, blank=True)
    webhook_branch = models.CharField(max_length=100, default='main', blank=True)
    # Maintain DB compatibility: some databases have a NOT NULL 'container_port'
    # We always expose container port 80 in Docker mapping, so set default=80
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
        """Model-level validations to ensure data integrity"""
        errors = {}

        # name required and unique per owner
        name = (self.name or '').strip()
        if not name:
            errors['name'] = ['Project name is required']
        elif self.owner_id:
            qs = Project.objects.filter(owner_id=self.owner_id, name__iexact=name)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                errors['name'] = ['You already have a project with this name']

        # github_repo_url basic format
        url = (self.github_repo_url or '').strip()
        if not url:
            errors['github_repo_url'] = ['GitHub repository URL is required']
        elif not (url.startswith('https://github.com/') or url.startswith('http://github.com/')):
            errors['github_repo_url'] = ['GitHub URL must start with https://github.com/']
        else:
            parts = url.replace('https://github.com/', '').replace('http://github.com/', '').split('/')
            if len(parts) < 2 or not parts[0] or not parts[1]:
                errors['github_repo_url'] = ['Invalid GitHub repository URL format']

        # exposed_port range and uniqueness
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

        # environment_variables should be valid (JSON object or KEY=VALUE lines)
        if self.environment_variables:
            try:
                parsed = self.get_env_variables()
                if not isinstance(parsed, dict):
                    errors['environment_variables'] = ['Environment variables must be a JSON object or KEY=VALUE lines']
            except Exception:
                errors['environment_variables'] = ['Environment variables must be valid JSON or KEY=VALUE lines']

        if errors:
            raise ValidationError(errors)
    
    def _is_port_free(self, port: int) -> bool:
        """Quick check if a TCP port is free on the host.
        Attempts to bind to 0.0.0.0:<port> and immediately releases it.
        Returns True if bind succeeds, otherwise False.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass
    
    def get_next_available_port(self):
        """Pick the first available port in the range 5000-5019.
        Checks both DB-assigned ports and whether the OS currently has the port in use.
        If all ports are taken, raises a RuntimeError.
        """
        allowed_ports = list(range(5000, 5020))
        # Ports already assigned to any project
        used_by_projects = set(
            Project.objects.exclude(exposed_port__isnull=True).values_list('exposed_port', flat=True)
        )
        # First pass: port not used in DB and free on host
        for p in allowed_ports:
            if p in used_by_projects:
                continue
            if self._is_port_free(p):
                return p
        # Fallback: pick first not used in DB (OS check might be unreliable in some environments)
        for p in allowed_ports:
            if p not in used_by_projects:
                return p
        # No ports free in range
        raise RuntimeError('No available port in the 5000-5019 range')
    
    def get_env_variables(self):
        """Parse environment variables from JSON or KEY=VALUE lines.
        - JSON: expects an object, e.g., {"KEY":"VALUE"}
        - Lines: one per line, KEY=VALUE; lines starting with # ignored.
        """
        raw = self.environment_variables or ''
        raw = raw.strip()
        if not raw:
            return {}
        # Try JSON first if it looks like JSON
        if raw.startswith('{'):
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                # fall through to line parsing
                pass
        # Parse KEY=VALUE lines
        env = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            if key:
                env[key] = value
        return env
    
    def deploy_with_docker(self, deployment):
        """Deploy project using Docker with minimal-downtime (blue-green):
        - Clean old clone dir (avoid 'already exists') then git clone
        - Build image
        - Run a staging container on a temporary port and health-check it
        - Stop old container to free the canonical port, start new container with a temporary name
        - If success: remove old and rename new -> canonical
        - Always cleanup staging container and clone dir
        """
        try:
            self.status = 'deploying'
            self.save()
            # helper to append log progressively
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

            # Ensure webhook token and exposed port
            if not self.webhook_token:
                self.webhook_token = uuid.uuid4().hex
                self.save()
            if not self.exposed_port:
                self.exposed_port = self.get_next_available_port()
                self.save()

            # Clone repository (clean target dir first to avoid 'already exists')
            repo_name = self.github_repo_url.split('/')[-1].replace('.git', '')
            tmp_dir = tempfile.gettempdir()
            clone_dir = os.path.join(tmp_dir, f"{repo_name}_{self.id}")
            # Try to clean target dir; if it still exists (Windows file locks), fall back to a unique dir
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
            
            # Optional: run custom build command in repo before docker build
            if self.build_command:
                append_log(f"Running custom build command in repo: {self.build_command}")
                try:
                    # Use shell=True to allow chained commands (e.g., npm install && npm run build)
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
                    # Clean up clone dir to avoid leaving temp files
                    shutil.rmtree(clone_dir, ignore_errors=True)
                    raise

            # Check Dockerfile
            dockerfile_path = os.path.join(clone_dir, self.dockerfile_path)
            if not os.path.exists(dockerfile_path):
                raise Exception(f"Dockerfile not found at {self.dockerfile_path}")

            # Detect container port from Dockerfile EXPOSE if available; fallback to model's container_port
            detected_container_port = None
            try:
                with open(dockerfile_path, 'r', encoding='utf-8', errors='ignore') as df:
                    for line in df:
                        line = line.strip()
                        if line.upper().startswith('EXPOSE'):
                            # Example formats: "EXPOSE 3000", "EXPOSE 3000/tcp", "EXPOSE 3000 8080"
                            parts = line.split()
                            for token in parts[1:]:
                                token = token.strip()
                                # strip protocol suffix
                                token = token.split('/')[0] if '/' in token else token
                                try:
                                    port_val = int(token)
                                    if 1 <= port_val <= 65535:
                                        detected_container_port = port_val
                                        break
                                except ValueError:
                                    continue
                            if detected_container_port:
                                break
            except Exception:
                detected_container_port = None

            container_port = detected_container_port or (self.container_port or 80)
            append_log(f"Using container internal port: {container_port}")

            # Build Docker image (stream logs)
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

            # Prepare env
            env_vars = self.get_env_variables()
            # Ensure common defaults for containerized apps
            env_vars.setdefault('HOST', '0.0.0.0')
            env_vars.setdefault('PORT', str(container_port))

            # Run STAGING container on a temporary free port
            staging_port = self.get_next_available_port()
            if staging_port == self.exposed_port:
                staging_port += 1
            staging_name = f"{repo_name}_{self.id}_staging"
            # Remove any stale staging container with the same name
            subprocess.run(['docker', 'rm', '-f', staging_name], capture_output=True)

            staging_cmd = ['docker', 'run', '-d', '-p', f"{staging_port}:{container_port}"]
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

            # Health check the staging container
            append_log("Health checking staging container...")
            healthy = False
            # Allow custom healthcheck path via env; fallback to common paths
            health_paths = []
            hc_path = env_vars.get('HEALTHCHECK_PATH')
            if isinstance(hc_path, str) and hc_path.strip():
                health_paths = [hc_path.strip()]
            else:
                health_paths = ['/', '/health', '/status', '/api/health', '/api/status', '/ping']
            # retries and interval configurable
            try:
                max_attempts = int(env_vars.get('HEALTHCHECK_RETRIES', 45))
            except Exception:
                max_attempts = 45
            try:
                interval = float(env_vars.get('HEALTHCHECK_INTERVAL', 2))
            except Exception:
                interval = 2
            # Accept 4xx as healthy if configured (many apps return 404 on root)
            accept_4xx = str(env_vars.get('HEALTHCHECK_ACCEPT_4XX', 'false')).lower() in ('1','true','yes','on')
            # Custom full URL support
            hc_full_url = str(env_vars.get('HEALTHCHECK_URL', '')).strip()
            # Candidate hosts: prefer host.docker.internal so web container can reach host-published port
            hc_host = str(env_vars.get('HEALTHCHECK_HOST', '')).strip()
            base_hosts = [hc_host] if hc_host else ['host.docker.internal', 'localhost']
            for _ in range(max_attempts):
                # Build URLs to try
                urls_to_try = []
                if hc_full_url.startswith('http://') or hc_full_url.startswith('https://'):
                    urls_to_try = [hc_full_url]
                else:
                    for host in base_hosts:
                        for path in health_paths:
                            path = path if path.startswith('/') else '/' + path
                            urls_to_try.append(f"http://{host}:{staging_port}{path}")
                for staging_url in urls_to_try:
                    try:
                        with urllib.request.urlopen(staging_url, timeout=3) as resp:
                            status = int(resp.getcode())
                        if (200 <= status < 400) or (accept_4xx and 400 <= status < 500):
                            healthy = True
                            break
                    except urllib.error.HTTPError as he:
                        try:
                            code = int(getattr(he, 'code', 0))
                        except Exception:
                            code = 0
                        if (200 <= code < 400) or (accept_4xx and 400 <= code < 500):
                            healthy = True
                            break
                    except Exception:
                        pass
                if healthy:
                    break
                time.sleep(interval)
            # TCP fallback: consider port open as healthy if configured (default true)
            if not healthy:
                tcp_enabled = str(env_vars.get('HEALTHCHECK_TCP', 'true')).lower() in ('1','true','yes','on')
                if tcp_enabled:
                    import socket as _socket
                    try:
                        tcp_attempts = int(env_vars.get('HEALTHCHECK_TCP_RETRIES', 10))
                    except Exception:
                        tcp_attempts = 10
                    try:
                        tcp_interval = float(env_vars.get('HEALTHCHECK_TCP_INTERVAL', 1))
                    except Exception:
                        tcp_interval = 1
                    for _ in range(tcp_attempts):
                        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                        s.settimeout(2)
                        try:
                            s.connect(('host.docker.internal', staging_port))
                            s.close()
                            healthy = True
                            break
                        except Exception:
                            try:
                                s.close()
                            except Exception:
                                pass
                            time.sleep(tcp_interval)
            if not healthy:
                # Show last logs from staging container to help diagnose
                logs = subprocess.run(['docker', 'logs', '--tail', '100', staging_container_id], capture_output=True, text=True)
                if logs.stdout:
                    append_log("[staging logs]" + ("\n" + logs.stdout))
                if logs.stderr:
                    append_log("[staging logs:stderr]" + ("\n" + logs.stderr))
                subprocess.run(['docker', 'rm', '-f', staging_container_id], capture_output=True)
                tried = ', '.join(health_paths)
                append_log(f"Staging container failed health check on host.docker.internal:{staging_port} (paths tried: {tried})")
                raise Exception("Staging health check failed")
            append_log("Staging container is healthy")

            # Switch traffic with minimal downtime
            canonical_name = f"{repo_name}_{self.id}"
            new_name = f"{canonical_name}_new"
            old_id = (self.docker_container_id or '').strip()

            # Stop old to free the port (do NOT remove yet)
            if old_id:
                subprocess.run(['docker', 'stop', old_id], capture_output=True)
                append_log("Stopped old container to free the port")

            # Ensure temp name not in use
            subprocess.run(['docker', 'rm', '-f', new_name], capture_output=True)

            final_cmd = ['docker', 'run', '--restart', 'unless-stopped', '-d', '-p', f"{self.exposed_port}:{container_port}"]
            for key, value in env_vars.items():
                final_cmd.extend(['-e', f"{key}={value}"])
            final_cmd.extend(['--name', new_name])
            final_cmd.append(image_name)
            if self.run_command:
                final_cmd.extend(self.run_command.split())
            append_log(f"Starting new container on port {self.exposed_port}...")
            final_result = subprocess.run(final_cmd, capture_output=True, text=True)
            if final_result.returncode != 0:
                # Rollback: cleanup new and start old back
                subprocess.run(['docker', 'rm', '-f', new_name], capture_output=True)
                if old_id:
                    subprocess.run(['docker', 'start', old_id], capture_output=True)
                subprocess.run(['docker', 'rm', '-f', staging_name], capture_output=True)
                append_log(final_result.stderr.strip())
                raise Exception("Docker run (final) failed")

            # Promote new: remove old and rename
            new_container_id = final_result.stdout.strip()
            if old_id:
                subprocess.run(['docker', 'rm', old_id], capture_output=True)
                append_log("Removed old container")
            try:
                subprocess.run(['docker', 'rename', new_name, canonical_name], capture_output=True)
            except Exception:
                # If rename fails (name conflict), force remove name and retry once
                subprocess.run(['docker', 'rm', '-f', canonical_name], capture_output=True)
                subprocess.run(['docker', 'rename', new_name, canonical_name], capture_output=True)
            append_log(f"Promoted new container to '{canonical_name}'")

            self.docker_container_id = new_container_id
            self.status = 'running'
            self.save()

            # Cleanup staging container and clone dir
            subprocess.run(['docker', 'rm', '-f', staging_name], capture_output=True)
            shutil.rmtree(clone_dir, ignore_errors=True)

            deployment.status = 'success'
            deployment.save(update_fields=['status'])
            append_log(f"Deployed successfully on port {self.exposed_port}")

            # Optional: replicate to remote hosts via SSH
            try:
                remote_hosts = getattr(settings, 'REMOTE_DEPLOY_HOSTS', []) or []
                ssh_user = getattr(settings, 'REMOTE_DEPLOY_SSH_USER', '') or ''
                ssh_key = getattr(settings, 'REMOTE_DEPLOY_SSH_KEY_PATH', '') or ''
                # Skip self if included (supports symmetric cluster configs)
                local_ip = getattr(settings, 'LOCAL_HOST_IP', '') or ''
                if not local_ip:
                    try:
                        # Try AWS IMDSv2 first
                        import requests as _requests
                        token = ''
                        try:
                            token = _requests.put(
                                'http://169.254.169.254/latest/api/token',
                                headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
                                timeout=1
                            ).text.strip()
                        except Exception:
                            token = ''
                        headers = {'X-aws-ec2-metadata-token': token} if token else {}
                        try:
                            local_ip = _requests.get(
                                'http://169.254.169.254/latest/meta-data/local-ipv4',
                                headers=headers,
                                timeout=1
                            ).text.strip()
                        except Exception:
                            local_ip = ''
                    except Exception:
                        local_ip = ''
                if local_ip:
                    remote_hosts = [h for h in remote_hosts if h != local_ip]
                # Resolve SSH key path: allow directory path, pick a .pem inside
                try:
                    import os as _os
                    resolved_ssh_key = ssh_key
                    if resolved_ssh_key and _os.path.isdir(resolved_ssh_key):
                        # Prefer common filenames
                        for _cand_name in ['backend-key.pem', 'id_rsa', 'id_ed25519']:
                            _cand = _os.path.join(resolved_ssh_key, _cand_name)
                            if _os.path.isfile(_cand):
                                resolved_ssh_key = _cand
                                break
                        # If still directory, pick first *.pem
                        if _os.path.isdir(resolved_ssh_key):
                            try:
                                _entries = _os.listdir(resolved_ssh_key)
                                _pem_entries = [e for e in _entries if e.lower().endswith('.pem')]
                                if _pem_entries:
                                    resolved_ssh_key = _os.path.join(resolved_ssh_key, _pem_entries[0])
                            except Exception:
                                pass
                    # If key path isn't a file after resolution, log and skip
                    if resolved_ssh_key and not _os.path.isfile(resolved_ssh_key):
                        append_log(f"SSH key path is not a file: {resolved_ssh_key}. Skipping remote replication.")
                        remote_hosts = []
                    else:
                        ssh_key = resolved_ssh_key
                except Exception:
                    pass

                if remote_hosts and ssh_user and ssh_key:
                    append_log(f"Replicating image to remote hosts via SSH: {', '.join(remote_hosts)}")
                    import tempfile as _tempfile
                    import uuid as _uuid
                    import os as _os
                    import subprocess as _subprocess
                    # Save image to tar
                    tar_path = _os.path.join(_tempfile.gettempdir(), f"{image_name}_{_uuid.uuid4().hex[:8]}.tar")
                    save_result = _subprocess.run(['docker', 'save', '-o', tar_path, image_name], capture_output=True, text=True)
                    if save_result.returncode != 0:
                        append_log("docker save failed: " + save_result.stderr.strip())
                    else:
                        try:
                            import paramiko as _paramiko
                            for host in remote_hosts:
                                try:
                                    append_log(f"Connecting to {host}...")
                                    client = _paramiko.SSHClient()
                                    client.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
                                    client.connect(hostname=host, username=ssh_user, key_filename=ssh_key, timeout=20)
                                    sftp = client.open_sftp()
                                    remote_tar = f"/tmp/{image_name}.tar"
                                    sftp.put(tar_path, remote_tar)
                                    sftp.close()
                                    # Build docker run command on remote
                                    canonical_name = f"{repo_name}_{self.id}"
                                    # Stop and remove existing
                                    cmds = [
                                        f"docker load -i {remote_tar}",
                                        f"docker rm -f {canonical_name} || true",
                                    ]
                                    # Compose env vars
                                    env_args = ' '.join([f"-e {k}={v}" for k, v in env_vars.items()])
                                    run_cmd = f"docker run --restart unless-stopped -d -p {self.exposed_port}:{container_port} {env_args} --name {canonical_name} {image_name}"
                                    if self.run_command:
                                        run_cmd = run_cmd + ' ' + self.run_command
                                    cmds.append(run_cmd)
                                    # Execute in one shell
                                    full_cmd = ' && '.join(cmds)
                                    stdin, stdout, stderr = client.exec_command(full_cmd, timeout=60)
                                    out = stdout.read().decode('utf-8', errors='ignore').strip()
                                    err = stderr.read().decode('utf-8', errors='ignore').strip()
                                    if out:
                                        append_log(f"[{host}] " + out)
                                    if err:
                                        append_log(f"[{host}:stderr] " + err)
                                    # Cleanup tar on remote
                                    client.exec_command(f"rm -f {remote_tar}")
                                    client.close()
                                    append_log(f"Replicated to {host} successfully")
                                except Exception as re:
                                    append_log(f"Remote deploy to {host} failed: {str(re)}")
                        except Exception as ie:
                            append_log(f"SSH replication failed: {str(ie)}")
                    try:
                        _os.remove(tar_path)
                    except Exception:
                        pass
                else:
                    append_log("Remote SSH deploy not configured; skipping.")
            except Exception as outer:
                append_log(f"Remote replication error: {str(outer)}")

            return True, "Deployment completed"
        except Exception as e:
            self.status = 'failed'
            self.save()
            deployment.status = 'failed'
            deployment.save(update_fields=['status'])
            append_log(f"Error: {str(e)}")
            return False, str(e)
    
    def stop_container(self):
        """Stop Docker container on local and all remote hosts"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Derive canonical and temporary container names for this project
            repo_name = self.github_repo_url.split('/')[-1].replace('.git', '')
            canonical_name = f"{repo_name}_{self.id}"
            staging_name = f"{repo_name}_{self.id}_staging"
            new_name = f"{canonical_name}_new"

            logger.info(f"Stopping containers: {canonical_name}, {new_name}, {staging_name}")

            # Stop on LOCAL host
            # Remove by container ID if present (force remove to ensure cleanup)
            if self.docker_container_id:
                result = subprocess.run(['docker', 'rm', '-f', self.docker_container_id], capture_output=True, text=True)
                logger.info(f"Local: Removed by ID {self.docker_container_id}: {result.stdout} {result.stderr}")

            # Also attempt to remove by known names to avoid name conflicts on next deploy
            for name in [canonical_name, new_name, staging_name]:
                result = subprocess.run(['docker', 'rm', '-f', name], capture_output=True, text=True)
                logger.info(f"Local: Removed {name}: {result.stdout} {result.stderr}")

            # Stop on REMOTE hosts via SSH
            try:
                remote_hosts = getattr(settings, 'REMOTE_DEPLOY_HOSTS', []) or []
                if isinstance(remote_hosts, str):
                    remote_hosts = [h.strip() for h in remote_hosts.split(',') if h.strip()]
                
                ssh_user = getattr(settings, 'REMOTE_DEPLOY_SSH_USER', '') or ''
                ssh_key = getattr(settings, 'REMOTE_DEPLOY_SSH_KEY_PATH', '') or ''
                
                logger.info(f"Remote hosts config: {remote_hosts}, user: {ssh_user}, key: {ssh_key}")
                
                # Skip self if included
                local_ip = getattr(settings, 'LOCAL_HOST_IP', '') or ''
                if not local_ip:
                    try:
                        import requests as _requests
                        token = ''
                        try:
                            token = _requests.put(
                                'http://169.254.169.254/latest/api/token',
                                headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
                                timeout=1
                            ).text.strip()
                        except Exception:
                            token = ''
                        headers = {'X-aws-ec2-metadata-token': token} if token else {}
                        try:
                            local_ip = _requests.get(
                                'http://169.254.169.254/latest/meta-data/local-ipv4',
                                headers=headers,
                                timeout=1
                            ).text.strip()
                        except Exception:
                            local_ip = ''
                    except Exception:
                        local_ip = ''
                
                logger.info(f"Local IP: {local_ip}")
                
                if local_ip:
                    remote_hosts = [h for h in remote_hosts if h != local_ip]
                
                logger.info(f"Remote hosts after filtering: {remote_hosts}")
                
                # Resolve SSH key path
                import os as _os
                resolved_ssh_key = ssh_key
                if resolved_ssh_key and _os.path.isdir(resolved_ssh_key):
                    for _cand_name in ['backend-key.pem', 'id_rsa', 'id_ed25519']:
                        _cand = _os.path.join(resolved_ssh_key, _cand_name)
                        if _os.path.isfile(_cand):
                            resolved_ssh_key = _cand
                            break
                    if _os.path.isdir(resolved_ssh_key):
                        pem_files = [f for f in _os.listdir(resolved_ssh_key) if f.endswith('.pem')]
                        if pem_files:
                            resolved_ssh_key = _os.path.join(resolved_ssh_key, pem_files[0])
                
                logger.info(f"Resolved SSH key: {resolved_ssh_key}")
                
                # Stop containers on each remote host
                if remote_hosts and ssh_user and resolved_ssh_key and _os.path.isfile(resolved_ssh_key):
                    for remote_host in remote_hosts:
                        try:
                            logger.info(f"Attempting SSH to {remote_host}")
                            
                            # Build stop commands
                            stop_cmds = []
                            for name in [canonical_name, new_name, staging_name]:
                                stop_cmds.append(f"docker rm -f {name} 2>/dev/null || true")
                            
                            remote_cmd = '; '.join(stop_cmds)
                            logger.info(f"Remote command: {remote_cmd}")
                            
                            # Execute via SSH
                            ssh_cmd = [
                                'ssh',
                                '-o', 'StrictHostKeyChecking=no',
                                '-o', 'UserKnownHostsFile=/dev/null',
                                '-o', 'ConnectTimeout=10',
                                '-i', resolved_ssh_key,
                                f"{ssh_user}@{remote_host}",
                                remote_cmd
                            ]
                            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
                            logger.info(f"SSH to {remote_host} result: stdout={result.stdout}, stderr={result.stderr}, returncode={result.returncode}")
                        except Exception as e:
                            logger.error(f"Failed SSH to {remote_host}: {e}")
                            # Continue even if one remote fails
                            pass
                else:
                    logger.warning(f"Skipping remote stop: hosts={bool(remote_hosts)}, user={bool(ssh_user)}, key={bool(resolved_ssh_key)}, key_exists={_os.path.isfile(resolved_ssh_key) if resolved_ssh_key else False}")
            except Exception as e:
                logger.error(f"Remote stop error: {e}")
                # Don't fail the whole operation if remote stop fails
                pass

            # Clear state
            self.docker_container_id = ''
            self.status = 'stopped'
            self.save()
            logger.info("Container stopped successfully on all hosts")
            return True, "Container stopped and removed successfully on all hosts"
        except Exception as e:
            logger.error(f"Stop container failed: {e}")
            return False, str(e)

    def check_container_status(self):
        """Check if container is actually running in Docker and update status"""
        # Derive canonical name (used across hosts)
        repo_name = self.github_repo_url.split('/')[-1].replace('.git', '')
        canonical_name = f"{repo_name}_{self.id}"
        if not self.docker_container_id:
            # Fallback: try to locate container by canonical name on this host
            try:
                find_cmd = ['docker', 'ps', '-q', '-f', f'name={canonical_name}']
                find_result = subprocess.run(find_cmd, capture_output=True, text=True)
                cid = (find_result.stdout or '').strip().splitlines()
                if cid:
                    self.docker_container_id = cid[0]
                    if self.status != 'running':
                        self.status = 'running'
                        self.save()
                    return True
            except Exception:
                pass
            # Not found by name; mark stopped
            if self.status == 'running':
                self.status = 'stopped'
                self.save()
            return False
            
        try:
            # Check container status using docker inspect
            cmd = ['docker', 'inspect', '--format', '{{.State.Running}}', self.docker_container_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # If command failed or container not running
            if result.returncode != 0 or result.stdout.strip().lower() != 'true':
                # If the stored ID is not running on this host, try to locate by name
                try:
                    find_cmd = ['docker', 'ps', '-q', '-f', f'name={canonical_name}']
                    find_result = subprocess.run(find_cmd, capture_output=True, text=True)
                    cid = (find_result.stdout or '').strip().splitlines()
                    if cid:
                        self.docker_container_id = cid[0]
                        if self.status != 'running':
                            self.status = 'running'
                            self.save()
                        return True
                except Exception:
                    pass
                # Not found: mark stopped
                if self.status == 'running':
                    self.status = 'stopped'
                    self.docker_container_id = ''
                    self.save()
                return False
                
            # Container is running
            if self.status != 'running':
                self.status = 'running'
                self.save()
            return True
            
        except Exception:
            # On any error, assume container is not running
            if self.status == 'running':
                self.status = 'stopped'
                self.docker_container_id = ''
                self.save()
            return False
    
    def get_preview_url(self):
        # First verify container is actually running
        is_running = self.check_container_status()
        if is_running and self.exposed_port:
            base = getattr(settings, 'PUBLIC_BASE_URL', '') or os.environ.get('PUBLIC_BASE_URL', '')
            if base:
                base = base.rstrip('/')

                if self.exposed_port:
                    return f"{base}:{self.exposed_port}/"
                return f"{base}/"
            return f"http://localhost:{self.exposed_port}/"
        return ""


class ProjectTag(models.Model):
    """Many-to-Many relationship between projects and tags"""
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'project_tags'
        unique_together = ['project', 'tag']


class Deployment(models.Model):
    """Model for storing deployment history"""
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


# APIKey model removed (deprecated feature)


class UserProfile(models.Model):
    """Model for storing user profile information"""
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
        """Get user's full name or username"""
        return self.user.get_full_name() or self.user.username
    
    def get_social_links(self):
        """Get all social media links"""
        links = {}
        if self.github_username:
            links['github'] = f"https://github.com/{self.github_username}"
        return links


class SocialAccount(models.Model):
    """Social accounts linked to a user (e.g., GitHub)"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='social_accounts')
    provider = models.CharField(max_length=50)  # e.g., 'github'
    uid = models.CharField(max_length=255)      # user id from provider
    extra_data = models.JSONField(default=dict) # arbitrary data from provider
    
    class Meta:
        db_table = 'social_accounts'
        unique_together = ['user', 'provider']
    
    def __str__(self):
        return f"{self.provider} - {self.user.username}"


# EnvironmentVariable model removed: environment vars are stored in Project.environment_variables JSON only
