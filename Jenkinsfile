pipeline {
  agent {
    docker {
      label 'linux'
      image 'golang:1.25.1-trixie'
      args '-v /etc/ssl/certs:/etc/ssl/certs:ro'
    }
  }
  stages {
    stage('test') {
      steps {
        withCredentials([string(credentialsId: 'oidc-id-token-example', variable: 'EXAMPLE_ID_TOKEN')]) {
          sh '''
            # dump the example id token. this is done in a way that prevents
            # jenkins from masking it from the job output.
            # NB this token is a secret. in a real pipeline you must never leak
            #    it like in this example.
            echo "$EXAMPLE_ID_TOKEN" | base64

            # build.
            HOME="$PWD" \
            CGO_ENABLED=0 \
              go build -ldflags="-s"

            # dump the example id token details.
            ./jenkins-validate-jwt EXAMPLE_ID_TOKEN
            '''.stripIndent()
        }
      }
    }
  }
}