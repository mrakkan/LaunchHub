from .models import SocialAccount

def github_connected(request):
    """Provide a global flag indicating whether the current user connected GitHub."""
    is_connected = False
    user = getattr(request, 'user', None)
    if user and user.is_authenticated:
        try:
            is_connected = SocialAccount.objects.filter(user=user, provider='github').exists()
        except Exception:
            is_connected = False
    return {
        'has_github_connected': is_connected
    }