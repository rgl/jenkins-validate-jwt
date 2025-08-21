pipeline {
  agent {
    label 'linux'
  }
  stages {
    stage('test') {
      steps {
        withCredentials([string(credentialsId: 'oidc-id-token-example', variable: 'EXAMPLE_ID_TOKEN')]) {
          sh '''
            echo "$EXAMPLE_ID_TOKEN" | base64
            docker run \
              --rm \
              -u "$(id -u):$(id -g)" \
              -v "/etc/ssl/certs:/etc/ssl/certs:ro" \
              -v "$(pwd):/workspace" \
              -w /workspace \
              -e HOME=/workspace \
              -e JENKINS_URL \
              -e EXAMPLE_ID_TOKEN \
              golang:1.25.0-trixie \
              sh -c 'CGO_ENABLED=0 go build -ldflags="-s" && ./jenkins-validate-jwt EXAMPLE_ID_TOKEN'
            '''.stripIndent()
        }
      }
    }
  }
}