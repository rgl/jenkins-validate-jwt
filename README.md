This validates a Jenkins CI OIDC ID Token JWT using the keys available at its JWKS endpoint.

A Jenkins CI OIDC ID Token JWT is a secret string that can be used to authenticate a particular CI job in 3rd party services (like HashiCorp Vault).

The OIDC ID Token JWT available in a CI job as a [environment variable provided by the IdTokenStringCredentials Credential Type](https://javadoc.jenkins.io/plugin/oidc-provider/io/jenkins/plugins/oidc_provider/IdTokenCredentials.html) (from the [OpenID Connect Provider Plugin](https://plugins.jenkins.io/oidc-provider)).

Its used from the pipeline as, e.g.:

```groovy
pipeline {
  agent {
    label 'linux'
  }
  stages {
    stage('test') {
      steps {
        withCredentials([string(credentialsId: 'oidc-id-token-example', variable: 'EXAMPLE_ID_TOKEN')]) {
          sh 'echo "$EXAMPLE_ID_TOKEN"'
        }
      }
    }
  }
}
```

A JWT is a structured string separated by dot characters; for example:

```
eyJraWQiOiJvaWRjLWlkLXRva2VuLWV4YW1wbGUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2plbmtpbnMuZXhhbXBsZS5jb20vb2lkYyIsImF1ZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJleHAiOjE3NTU4MDQxMDMsImlhdCI6MTc1NTgwMDUwMywic3ViIjoiaHR0cHM6Ly9qZW5raW5zLmV4YW1wbGUuY29tL2pvYi9qZW5raW5zLXZhbGlkYXRlLWp3dC8iLCJidWlsZF9udW1iZXIiOjF9.Ov8XEe2qKSky9ZTQU6KJWxD4-zSTIu9-z7Vfqee6NtWwJyP9DMAEF00Ss_VdQY85M01adrIEytkToHUNKtYnc8uSiYxXY9GFLdeU0KJ8y3V6BFxx3yclJsEwc30ggHvY1ZZLtGSbXqi4xNddouxP5z3gdW-AlPdkldp4Cjmq4vnGbSaMeuV904F3vS4f8EdJsEYRTMUlQ0qQwTJCeu61xTaqUORKB8KKOTBHetR76PmUwgZXoX48YDJzQrXFRVwRu6-SKE8tHbKLj3jxvuDT_aOrKms8SGbgtdkA98mg_YiQKKK1683L1jnRL8yO1jgIQWs6GnIZxC3A6qCQF1BiTA
```

When split by dot and decoded it has a header, payload and signature.

In this case, the header is:

```json
{
  "kid": "oidc-id-token-example",
  "alg": "RS256"
}
```

The payload is:

```json
{
  "iss": "https://jenkins.example.com/oidc",
  "aud": "https://example.com",
  "exp": 1755804103,
  "iat": 1755800503,
  "sub": "https://jenkins.example.com/job/jenkins-validate-jwt/",
  "build_number": 1
}
```

And the signature is the value from the 3rd part of the JWT string.

Before a JWT can be used it must be validated. In this particular example the JWT can be validated with:

```go
RSASHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  jenkinsJwtKeySet.getPublicKey(header.kid))
```

The above public key should be retrieved from the Jenkins JWKS endpoint (e.g. https://jenkins.example.com/oidc/jwks).

To see how all of this can be done read the [main.go](main.go) file.

This project is used to test the jenkins playground at [rgl/jenkins-vagrant](https://github.com/rgl/jenkins-vagrant).
