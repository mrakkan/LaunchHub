from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden, HttpResponseBadRequest
from .models import Project, Deployment, UserProfile, SocialAccount, Tag, ProjectTag
from django.utils import timezone
from django.utils.text import slugify
import requests
from django.conf import settings
import secrets
import json
from django.db.models import Q
import hmac
import hashlib
from django.views.decorators.csrf import csrf_exempt
from .forms import SignUpForm, ProjectForm


def home(request):
    """หน้าแรกของเว็บไซต์"""
    return render(request, 'core/home.html')


def user_login(request):
    """หน้าเข้าสู่ระบบ"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('core:dashboard')
        else:
            messages.error(request, 'Invalid username or password')
    
    return render(request, 'core/login.html')


def user_logout(request):
    """ออกจากระบบ"""
    logout(request)
    messages.success(request, 'You have been logged out successfully')
    return redirect('core:home')


def signup(request):
    """สมัครสมาชิก"""
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Account created successfully! Please log in.')
            return redirect('core:user_login')
        return render(request, 'core/signup.html', {'form': form})
    form = SignUpForm()
    return render(request, 'core/signup.html', {'form': form})

def github_login(request):
    """เริ่มกระบวนการ GitHub OAuth"""
    github_auth_url = 'https://github.com/login/oauth/authorize'
    params = {
        'client_id': settings.GITHUB_CLIENT_ID,
        'redirect_uri': settings.GITHUB_REDIRECT_URI,
        'scope': 'user:email repo',
        'state': secrets.token_urlsafe(32)
    }
    
    # เก็บ state ใน session เพื่อตรวจสอบความปลอดภัย
    request.session['github_oauth_state'] = params['state']
    # โหมดเชื่อมบัญชี: ถ้าผู้ใช้ล็อกอินอยู่ แปลว่าต้องการเชื่อม GitHub เข้ากับบัญชีปัจจุบัน
    request.session['github_connect_mode'] = bool(request.user.is_authenticated)
    
    auth_url = f"{github_auth_url}?client_id={params['client_id']}&redirect_uri={params['redirect_uri']}&scope={params['scope']}&state={params['state']}"
    return redirect(auth_url)

def github_callback(request):
    """รับ callback จาก GitHub OAuth"""
    code = request.GET.get('code')
    state = request.GET.get('state')
    
    # ตรวจสอบ state เพื่อความปลอดภัย
    if not state or state != request.session.get('github_oauth_state'):
        messages.error(request, 'Invalid OAuth state')
        return redirect('core:user_login')
    
    if not code:
        messages.error(request, 'No authorization code received')
        return redirect('core:user_login')
    
    # ขอ access token จาก GitHub
    token_url = 'https://github.com/login/oauth/access_token'
    token_data = {
        'client_id': settings.GITHUB_CLIENT_ID,
        'client_secret': settings.GITHUB_CLIENT_SECRET,
        'code': code,
        'redirect_uri': settings.GITHUB_REDIRECT_URI
    }
    
    headers = {'Accept': 'application/json'}
    token_response = requests.post(token_url, data=token_data, headers=headers)
    
    if token_response.status_code != 200:
        messages.error(request, 'Failed to get access token')
        return redirect('core:user_login')
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    if not access_token:
        messages.error(request, 'No access token received')
        return redirect('core:user_login')
    
    # ขอข้อมูลผู้ใช้จาก GitHub
    user_url = 'https://api.github.com/user'
    user_headers = {
        'Authorization': f'token {access_token}',
        'Accept': 'application/json'
    }
    
    user_response = requests.get(user_url, headers=user_headers)
    
    if user_response.status_code != 200:
        messages.error(request, 'Failed to get user data')
        return redirect('core:user_login')
    
    user_data = user_response.json()
    github_username = user_data.get('login')
    github_email = user_data.get('email')
    avatar_url = user_data.get('avatar_url')
    
    if not github_username:
        messages.error(request, 'No GitHub username received')
        return redirect('core:user_login')
    
    # ใช้ email จาก GitHub หรือดึงจาก /user/emails ถ้าไม่มี
    if not github_email:
        emails_resp = requests.get('https://api.github.com/user/emails', headers=user_headers)
        if emails_resp.status_code == 200:
            try:
                emails = emails_resp.json()
                primary_email = next((e.get('email') for e in emails if e.get('primary')), None)
                if primary_email:
                    github_email = primary_email
            except Exception:
                pass
    
    if not github_email:
        github_email = f"{github_username}@github.local"
    
    # โหมดการเชื่อมต่อหรือเข้าสู่ระบบด้วย GitHub
    uid = str(user_data.get('id') or github_username)
    connect_mode = bool(request.session.get('github_connect_mode')) and request.user.is_authenticated
    # เคลียร์ flag ทันทีหลังใช้งาน
    request.session.pop('github_connect_mode', None)

    if connect_mode:
        # เชื่อม GitHub เข้ากับบัญชีปัจจุบัน โดยไม่แก้ username/email/avatar เดิม
        current_user = request.user
        try:
            profile = current_user.profile
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=current_user)

        # กำหนด github_username ถ้าว่างเท่านั้น
        if not profile.github_username:
            profile.github_username = github_username or ''
        # ตั้ง avatar จาก GitHub เฉพาะกรณีที่ยังไม่มีรูปเดิม
        if avatar_url and not profile.avatar_url:
            profile.avatar_url = avatar_url
        profile.save()

        SocialAccount.objects.update_or_create(
            user=current_user,
            provider='github',
            defaults={
                'uid': uid,
                'extra_data': {
                    'access_token': access_token,
                    'user_data': user_data,
                    'avatar_url': avatar_url,
                }
            }
        )
        messages.success(request, 'เชื่อมต่อ GitHub กับบัญชีของคุณเรียบร้อยแล้ว')
        return redirect('core:edit_profile')
    else:
        # เข้าสู่ระบบด้วย GitHub (ผู้ใช้ยังไม่ล็อกอิน)
        existing = SocialAccount.objects.filter(provider='github', uid=uid).first()
        if existing:
            user = existing.user
            # เติม email เฉพาะกรณีว่าง
            if github_email and not user.email:
                user.email = github_email
                user.save()
            # ดูแลโปรไฟล์โดยไม่ทับข้อมูลเดิม
            try:
                profile = user.profile
            except UserProfile.DoesNotExist:
                profile = UserProfile.objects.create(user=user)
            if not profile.github_username:
                profile.github_username = github_username or ''
            if avatar_url and not profile.avatar_url:
                profile.avatar_url = avatar_url
            profile.save()
            login(request, user)
            messages.success(request, f'Logged in with GitHub as {github_username}')
            return redirect('core:dashboard')

        # ไม่พบ SocialAccount: สร้างผู้ใช้ใหม่ โดยพยายามหลีกเลี่ยงการชนกับ username ที่มีอยู่
        base_username = github_username or f'github_{uid}'
        username = base_username
        try:
            User.objects.get(username=username)
            suffix = 1
            while True:
                candidate = f"{base_username}_{suffix}"
                try:
                    User.objects.get(username=candidate)
                    suffix += 1
                except User.DoesNotExist:
                    username = candidate
                    break
        except User.DoesNotExist:
            pass

        user = User.objects.create_user(
            username=username,
            email=github_email or '',
            password=secrets.token_urlsafe(32)
        )
        profile = UserProfile.objects.create(user=user)
        profile.github_username = github_username or ''
        if avatar_url:
            profile.avatar_url = avatar_url
        profile.save()
        SocialAccount.objects.create(
            user=user,
            provider='github',
            uid=uid,
            extra_data={
                'access_token': access_token,
                'user_data': user_data,
                'avatar_url': avatar_url,
            }
        )
        login(request, user)
        messages.success(request, f'Logged in with GitHub as {github_username}')
        return redirect('core:dashboard')


@login_required
def dashboard(request):
    """แดชบอร์ดหลังจากเข้าสู่ระบบ"""
    projects = Project.objects.filter(owner=request.user).order_by('-created_at')
    
    # Deployments
    recent_deployments = Deployment.objects.filter(
        project__owner=request.user
    ).order_by('-timestamp')[:10]
    recent_projects = Project.objects.filter(owner=request.user).order_by('-updated_at')[:5]

    # ตรวจสอบสถานะ container จริงจาก Docker สำหรับทุกโปรเจกต์ที่มีสถานะ 'running'
    running_projects = Project.objects.filter(owner=request.user, status='running')
    for project in running_projects:
        project.check_container_status()  # อัพเดทสถานะตามสถานะ container จริง
    
    # ดึงข้อมูลโปรเจกต์ที่รันอยู่อีกครั้งหลังจากอัพเดทสถานะแล้ว
    active_projects = Project.objects.filter(owner=request.user, status='running')
    pending_deployments = Deployment.objects.filter(project__owner=request.user, status='in_progress')
    
    context = {
        'projects': projects,
        'active_projects': active_projects,
        'pending_deployments': pending_deployments,
        'recent_deployments': recent_deployments,
        'recent_projects': recent_projects,
    }
    return render(request, 'core/dashboard.html', context)


@login_required
def project_list(request):
    """รายการโปรเจกต์ทั้งหมด"""
    projects = Project.objects.filter(owner=request.user).order_by('-created_at')
    return render(request, 'core/project_list.html', {'projects': projects})


@login_required
def project_detail(request, project_id):
    """Project detail page showing info, env vars, and deployment history"""
    project = get_object_or_404(Project, id=project_id)
    if project.owner != request.user:
        return HttpResponseForbidden("You do not have access to this project")
    
    # ตรวจสอบสถานะ container จริงจาก Docker
    if project.status == 'running':
        project.check_container_status()
        
    deployments = Deployment.objects.filter(project=project).order_by('-timestamp')
    return render(request, 'core/project_detail.html', {
        'project': project,
        'deployments': deployments,
    })

@login_required
def create_project(request):
    """Create a new project"""
    if request.method == 'POST':
        # Require GitHub connection before allowing project creation
        has_github_connected = SocialAccount.objects.filter(user=request.user, provider='github').exists()
        if not has_github_connected:
            messages.warning(request, 'Please connect your GitHub account before creating a project.')
            return render(request, 'core/create_project.html', {
                'has_github_connected': False,
                'github_repos': [],
                'require_github': True,
                'form': ProjectForm(user=request.user),
            })

        form = ProjectForm(request.POST, user=request.user)
        if form.is_valid():
            try:
                project = form.save()
            except Exception as e:
                messages.error(request, f'ไม่สามารถกำหนดพอร์ตอัตโนมัติได้ (ช่วง 5000–5019): {e}')
                # If error during save, re-fetch repos for better UX
                github_repos = []
                try:
                    acct = SocialAccount.objects.filter(user=request.user, provider='github').first()
                    if acct and acct.extra_data.get('access_token'):
                        token = acct.extra_data.get('access_token')
                        headers = {
                            'Authorization': f'token {token}',
                            'Accept': 'application/vnd.github+json'
                        }
                        try:
                            resp = requests.get('https://api.github.com/user/repos?per_page=50&sort=updated', headers=headers, timeout=10)
                            if resp.status_code == 200:
                                github_repos = resp.json()
                        except Exception:
                            github_repos = []
                except Exception:
                    github_repos = []

                return render(request, 'core/create_project.html', {
                    'has_github_connected': True,
                    'github_repos': github_repos,
                    'require_github': False,
                    'form': form,
                })
            messages.success(request, 'Project created successfully!')
            return redirect('core:project_detail', project_id=project.id)

        # If invalid, re-fetch repos if connected for better UX
        github_repos = []
        try:
            acct = SocialAccount.objects.filter(user=request.user, provider='github').first()
            if acct and acct.extra_data.get('access_token'):
                token = acct.extra_data.get('access_token')
                headers = {
                    'Authorization': f'token {token}',
                    'Accept': 'application/vnd.github+json'
                }
                try:
                    resp = requests.get('https://api.github.com/user/repos?per_page=50&sort=updated', headers=headers, timeout=10)
                    if resp.status_code == 200:
                        github_repos = resp.json()
                except Exception:
                    github_repos = []
        except Exception:
            github_repos = []

        return render(request, 'core/create_project.html', {
            'has_github_connected': True,
            'github_repos': github_repos,
            'require_github': False,
            'form': form,
        })

    # GET: optionally fetch GitHub repos if connected
    github_repos = []
    has_github_connected = False
    try:
        acct = SocialAccount.objects.filter(user=request.user, provider='github').first()
        if acct and acct.extra_data.get('access_token'):
            has_github_connected = True
            token = acct.extra_data.get('access_token')
            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github+json'
            }
            try:
                resp = requests.get('https://api.github.com/user/repos?per_page=50&sort=updated', headers=headers, timeout=10)
                if resp.status_code == 200:
                    github_repos = resp.json()
            except Exception:
                github_repos = []
    except Exception:
        has_github_connected = False

    return render(request, 'core/create_project.html', {
        'has_github_connected': has_github_connected,
        'github_repos': github_repos,
        'require_github': not has_github_connected,
        'form': ProjectForm(user=request.user),
    })

@login_required
def deploy_project(request, project_id):
    """Trigger deployment for a project and return JSON result"""
    if request.method != 'POST':
        return HttpResponseBadRequest('Invalid method')
    project = get_object_or_404(Project, id=project_id)
    if project.owner != request.user:
        return JsonResponse({'success': False, 'message': 'Not authorized'}, status=403)

    # create deployment record
    deployment = Deployment.objects.create(project=project, status='in_progress', log='Starting deployment...')

    success, message = project.deploy_with_docker(deployment)
    # Timestamp completion; log and status are updated during deployment
    deployment.timestamp = timezone.now()
    deployment.save()

    return JsonResponse({'success': success, 'message': message})

@login_required
def deployment_detail(request, deployment_id):
    """Show details for a specific deployment"""
    deployment = get_object_or_404(Deployment, id=deployment_id)
    if deployment.project.owner != request.user:
        return HttpResponseForbidden("You do not have access to this deployment")

    recent_deployments = Deployment.objects.filter(project=deployment.project).order_by('-timestamp')[:10]
    return render(request, 'core/deployment_detail.html', {
        'deployment': deployment,
        'recent_deployments': recent_deployments,
    })

@login_required
def deployment_log_api(request, deployment_id):
    """API endpoint to fetch deployment log and status in JSON format"""
    deployment = get_object_or_404(Deployment, id=deployment_id)
    if deployment.project.owner != request.user:
        return JsonResponse({'error': 'Not authorized'}, status=403)
    
    return JsonResponse({
        'log': deployment.log or '',
        'status': deployment.status,
        'timestamp': deployment.timestamp.isoformat() if deployment.timestamp else None
    })

@login_required
def stop_project(request, project_id):
    """Stop a running project's container"""
    if request.method != 'POST':
        return HttpResponseBadRequest('Invalid method')
    project = get_object_or_404(Project, id=project_id)
    if project.owner != request.user:
        return JsonResponse({'success': False, 'message': 'Not authorized'}, status=403)

    success, message = project.stop_container()
    return JsonResponse({'success': success, 'message': message})

@login_required
def delete_project(request, project_id):
    """Delete a project and its resources"""
    if request.method != 'POST':
        return HttpResponseBadRequest('Invalid method')
    project = get_object_or_404(Project, id=project_id)
    if project.owner != request.user:
        return JsonResponse({'success': False, 'message': 'Not authorized'}, status=403)

    # Attempt to stop container if running
    try:
        project.stop_container()
    except Exception:
        pass

    project.delete()
    messages.success(request, 'Project deleted successfully')
    return JsonResponse({'success': True})

# add_env_var/delete_env_var removed; env vars managed via Project.environment_variables JSON only

@login_required
def profile(request):
    """View own profile"""
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user)
    has_github_connected = SocialAccount.objects.filter(user=request.user, provider='github').exists()
    projects_count = Project.objects.filter(owner=request.user).count()
    deployments_count = Deployment.objects.filter(project__owner=request.user).count()
    return render(request, 'core/profile.html', {
        'user': request.user,
        'profile': profile,
        'has_github_connected': has_github_connected,
        'projects_count': projects_count,
        'deployments_count': deployments_count,
    })

@login_required
def edit_profile(request):
    """Edit own profile"""
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user)
    has_github_connected = SocialAccount.objects.filter(user=request.user, provider='github').exists()
    if request.method == 'POST':
        # Update core User fields
        user = request.user
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        email = request.POST.get('email', '').strip()
        if email:
            user.email = email
        user.save()

        # Update Profile fields
        profile.bio = request.POST.get('bio', '').strip()
        profile.company = request.POST.get('company', '').strip()
        profile.location = request.POST.get('location', '').strip()
        profile.website = request.POST.get('website', '').strip()
        profile.github_username = request.POST.get('github_username', '').strip()

        # Only update avatar_url if a non-empty value is provided
        new_avatar_url = request.POST.get('avatar_url', '').strip()
        if new_avatar_url:
            profile.avatar_url = new_avatar_url
        # If no avatar_url provided, keep existing avatar_url (avoid overwriting with empty string)

        profile.save()
        messages.success(request, 'Profile updated successfully')
        return redirect('core:profile')
    return render(request, 'core/edit_profile.html', {
        'profile': profile,
        'has_github_connected': has_github_connected,
    })

@login_required
def change_password(request):
    """Change account password"""
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        if not request.user.check_password(old_password):
            messages.error(request, 'Current password is incorrect')
        elif not new_password:
            messages.error(request, 'New password cannot be empty')
        elif new_password != confirm_password:
            messages.error(request, 'Passwords do not match')
        else:
            request.user.set_password(new_password)
            request.user.save()
            messages.success(request, 'Password changed successfully. Please log in again.')
            return redirect('core:user_login')
    return render(request, 'core/change_password.html')

def explore_projects(request):
    """Public explore page showing only public projects"""
    q = request.GET.get('q', '').strip()
    tag_slug = request.GET.get('tag', '').strip()
    
    projects = Project.objects.filter(is_public=True)
    
    # Filter by search query
    if q:
        projects = projects.filter(Q(name__icontains=q))
    
    # Filter by tag
    selected_tag_name = ""
    if tag_slug:
        tag = get_object_or_404(Tag, slug=tag_slug)
        projects = projects.filter(tags=tag)
        selected_tag_name = tag.name
    
    # Get all tags for filter dropdown
    all_tags = Tag.objects.all().order_by('name')
    
    projects = projects.order_by('-updated_at')[:100]
    return render(request, 'core/explore_projects.html', {
        'projects': projects, 
        'q': q,
        'all_tags': all_tags,
        'selected_tag': tag_slug,
        'selected_tag_name': selected_tag_name
    })

@login_required
def add_project_tag(request):
    """Add a tag to a project"""
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        tag_name = request.POST.get('tag_name', '').strip()
        
        if not tag_name:
            return JsonResponse({'status': 'error', 'message': 'Tag name is required'})
            
        project = get_object_or_404(Project, id=project_id, owner=request.user)
        
        # Get or create the tag
        tag, created = Tag.objects.get_or_create(
            name=tag_name,
            defaults={'slug': slugify(tag_name)}
        )
        
        # Add tag to project if not already added
        if not ProjectTag.objects.filter(project=project, tag=tag).exists():
            ProjectTag.objects.create(project=project, tag=tag)
            return JsonResponse({'status': 'success', 'tag_id': tag.id, 'tag_name': tag.name})
        else:
            return JsonResponse({'status': 'error', 'message': 'Tag already exists for this project'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'})

@login_required
def remove_project_tag(request):
    """Remove a tag from a project"""
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        tag_id = request.POST.get('tag_id')
        
        project = get_object_or_404(Project, id=project_id, owner=request.user)
        tag = get_object_or_404(Tag, id=tag_id)
        
        # Remove the tag from the project
        ProjectTag.objects.filter(project=project, tag=tag).delete()
        
        return JsonResponse({'status': 'success'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'})
def public_profile(request, username):
    """Public profile page for a user, showing their public projects"""
    target_user = get_object_or_404(User, username=username)
    try:
        target_profile = target_user.profile
    except UserProfile.DoesNotExist:
        target_profile = UserProfile.objects.create(user=target_user)
    has_github_connected = SocialAccount.objects.filter(user=target_user, provider='github').exists()
    projects_count = Project.objects.filter(owner=target_user, is_public=True).count()
    deployments_count = Deployment.objects.filter(project__owner=target_user).count()
    public_projects = Project.objects.filter(owner=target_user, is_public=True).order_by('-updated_at')
    # Do NOT override 'user' in context (keeps request.user for auth checks)
    # Provide display_user/display_profile for template to render target user's data
    return render(request, 'core/profile.html', {
        'display_user': target_user,
        'display_profile': target_profile,
        'has_github_connected': has_github_connected,
        'projects_count': projects_count,
        'deployments_count': deployments_count,
        'projects': public_projects,
        'is_public_profile': True,
    })

@login_required
def github_disconnect(request):
    """Disconnect GitHub from current user account"""
    if request.method == 'POST':
        SocialAccount.objects.filter(user=request.user, provider='github').delete()
        try:
            profile = request.user.profile
            # เคลียร์ github_username แต่คง avatar_url เดิมไว้
            profile.github_username = ''
            profile.save()
        except UserProfile.DoesNotExist:
            pass
        # ล้าง state เศษจาก OAuth ถ้ามี
        request.session.pop('github_oauth_state', None)
        messages.success(request, 'ยกเลิกการเชื่อมต่อ GitHub เรียบร้อยแล้ว')
        return redirect('core:edit_profile')
    return redirect('core:edit_profile')
@csrf_exempt
def github_webhook(request, project_id):
    """Webhook endpoint to trigger deployments from GitHub push events"""
    project = get_object_or_404(Project, id=project_id)
    if not project.webhook_enabled:
        return JsonResponse({'success': False, 'message': 'Webhook disabled'}, status=403)

    # Validate signature if provided
    signature = request.headers.get('X-Hub-Signature-256')
    body = request.body
    if project.webhook_token and signature:
        try:
            sha_name, sig = signature.split('=')
            mac = hmac.new(project.webhook_token.encode('utf-8'), msg=body, digestmod=hashlib.sha256)
            expected = mac.hexdigest()
            if not hmac.compare_digest(sig, expected):
                return HttpResponseForbidden('Invalid signature')
        except Exception:
            return HttpResponseBadRequest('Malformed signature header')

    event = request.headers.get('X-GitHub-Event')
    if event != 'push':
        return JsonResponse({'success': True, 'message': 'Event ignored'})

    try:
        payload = json.loads(body.decode('utf-8'))
    except Exception:
        payload = {}

    # Branch filter
    ref = payload.get('ref', '')  # e.g., refs/heads/main
    branch = ref.split('/')[-1] if ref else ''
    if project.webhook_branch and branch and branch != project.webhook_branch:
        return JsonResponse({'success': True, 'message': f'Ignored branch {branch}'})

    # Create deployment record with commit hash
    commit_hash = ''
    try:
        commit_hash = payload.get('after', '')
    except Exception:
        pass

    deployment = Deployment.objects.create(project=project, status='in_progress', commit_hash=commit_hash, log='Triggered by GitHub webhook')
    success, message = project.deploy_with_docker()
    deployment.log = (deployment.log or '') + f"\n{message}"
    deployment.status = 'success' if success else 'failed'
    deployment.timestamp = timezone.now()
    deployment.save()

    return JsonResponse({'success': success, 'message': message})

def health_check(request):
    return JsonResponse({'status': 'ok', 'time': timezone.now().isoformat()})