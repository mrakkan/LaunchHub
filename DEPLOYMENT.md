AWS EC2 Deployment (RDS-backed)

Goal: Run `docker compose up -d --build` on your EC2 instance and have the site available at `http://<EC2-IP>:8080/` (or via your ALB).

Prerequisites
- An EC2 instance (Amazon Linux 2 or Ubuntu 22.04 works well)
- Security Group allows inbound `HTTP` to your chosen port (default host `8080`) and `SSH (22)` from your admin IP
- RDS PostgreSQL instance reachable from the EC2 Security Group

Install Docker and Docker Compose
- Amazon Linux 2:
  ```bash
  sudo yum update -y
  sudo amazon-linux-extras enable docker
  sudo yum install -y docker
  sudo systemctl enable docker
  sudo systemctl start docker
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
  sudo systemctl enable docker
  sudo systemctl start docker
  sudo usermod -a -G docker $USER
  # Log out/in to apply docker group
  docker compose version
  ```

Deploy the App
```bash
git clone <your-repo-url> && cd EasyDeploy
# Ensure RDS is reachable from EC2 SG and credentials are configured in Django settings
# Optionally set SSL mode via env: DB_SSLMODE=require
docker compose up -d --build
```

What this does
- Builds and starts the web container (restart policy: `unless-stopped`)
- Runs Django migrations against your RDS PostgreSQL
- Serves the app via `runserver` on container port `8000`, mapped to host `8080`

Auto-start on reboot
- The platform web container uses `restart: unless-stopped` and will auto-start when Docker starts
- User app containers launched by EasyDeploy also use `--restart unless-stopped` and will auto-start on both Machine A and Machine B
- Make sure Docker service is enabled on boot: `sudo systemctl enable docker`

Open in Browser
- Visit `http://<EC2-IP>:8080/`
- If behind an ALB, forward traffic to instance port `8080` (or adapt the mapping)

Notes
- No local Postgres container is used; the app connects to your RDS instance.
- Ensure your RDS Security Group allows inbound `TCP 5432` from the EC2 instance's Security Group.
- `DB_SSLMODE` can be set via environment (default in settings is `prefer`). For production, use `require`.
- Static files are stored in `/app/staticfiles` and served by the app. Consider an Nginx reverse proxy when adding a domain and HTTPS.