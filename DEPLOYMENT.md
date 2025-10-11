AWS EC2 Deployment (One Command)

Goal: Run `docker compose up -d` on your EC2 instance and have the site publicly available at `http://<EC2-IP>/`.

Prerequisites
- An EC2 instance (Amazon Linux 2 or Ubuntu 22.04 works well)
- Security Group allows inbound `HTTP (80)` and `SSH (22)` from your IP
- Git installed, or download the repo via ZIP

Install Docker and Docker Compose
- Amazon Linux 2:
  ```bash
  sudo yum update -y
  sudo amazon-linux-extras enable docker
  sudo yum install -y docker
  sudo service docker start
  sudo usermod -a -G docker $USER
  # Log out/in to apply docker group
  curl -L "https://github.com/docker/compose/releases/download/v2.27.0/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
  docker compose version || docker-compose --version
  ```
- Ubuntu:
  ```bash
  sudo apt update && sudo apt install -y ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt update
  sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo usermod -a -G docker $USER
  # Log out/in to apply docker group
  docker compose version
  ```

Deploy the App
```bash
git clone <your-repo-url> && cd EasyDeploy
docker compose up -d
```

What this does
- Starts Postgres as `db` with credentials matching Django settings
- Builds the web container, runs migrations, collects static, and serves via Gunicorn
- Maps container port `8000` to host `80` so the app is available at `http://<EC2-IP>/`

Open in Browser
- Visit `http://<EC2-IP>/`

Notes
- GitHub OAuth: If you want to use login with GitHub on EC2, update your OAuth App's Authorization callback URL to `http://<EC2-IP>/github/callback/` in GitHub settings.
- Static files: Collected to `/app/staticfiles` and served directly by the app. If you later add a domain and HTTPS, consider an Nginx reverse proxy.
- Database: The DB runs inside Docker. To persist across restarts, we use the `pgdata` volume.