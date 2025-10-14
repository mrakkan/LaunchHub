// Main JavaScript file for Deploy Platform

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Deployment log auto-refresh
    setupDeploymentLogRefresh();

    // Form validations
    setupFormValidations();
});

// Setup auto-refresh for deployment logs
function setupDeploymentLogRefresh() {
    const deploymentLog = document.getElementById('deployment-log');
    if (deploymentLog) {
        const deploymentId = deploymentLog.getAttribute('data-deployment-id');
        if (deploymentId) {
            // Auto-refresh every 5 seconds if deployment is in progress
            const isDeploying = deploymentLog.getAttribute('data-deploying') === 'true';
            if (isDeploying) {
                setInterval(() => {
                    fetchDeploymentLog(deploymentId);
                }, 5000);
            }
        }
    }
}

// Fetch deployment log updates
function fetchDeploymentLog(deploymentId) {
    fetch(`/api/deployments/${deploymentId}/log/`)
        .then(response => response.json())
        .then(data => {
            const deploymentLog = document.getElementById('deployment-log');
            if (deploymentLog) {
                deploymentLog.textContent = data.log;
                
                // Scroll to bottom of log
                deploymentLog.scrollTop = deploymentLog.scrollHeight;
                
                // Update status if deployment is complete
                if (data.status !== 'deploying') {
                    deploymentLog.setAttribute('data-deploying', 'false');
                    const statusBadge = document.getElementById('deployment-status');
                    if (statusBadge) {
                        statusBadge.className = ''; // Remove all classes
                        statusBadge.classList.add('badge', data.status === 'running' ? 'bg-success' : 'bg-danger');
                        statusBadge.textContent = data.status === 'running' ? 'Running' : 'Failed';
                    }
                }
            }
        })
        .catch(error => console.error('Error fetching deployment log:', error));
}

// Setup form validations
function setupFormValidations() {
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });
}

// Get CSRF token from cookies
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}