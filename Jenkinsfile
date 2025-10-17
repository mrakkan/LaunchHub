pipeline {
  agent any
  options { timestamps() }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }
    stage('Build & Deploy') {
      steps {
        sh 'docker-compose pull || true'
        sh 'docker-compose build'
        sh 'docker-compose up -d --remove-orphans'
        sh 'sudo systemctl reload nginx'
        sh 'docker-compose ps'
      }
    }
  }

  post {
    always {
      echo 'Pipeline finished.'
    }
    failure {
      echo 'Deployment failed. ตรวจ Jenkins console และ docker compose logs เพื่อหา error message ที่เกิดขึ้น'
    }
  }
}