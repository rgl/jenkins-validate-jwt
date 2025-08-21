package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func getEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("the %s environment variable must be set", name)
	}
	return v
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("you must pass the id token environment variable name as the single command line argument")
	}
	ciJobJWT := getEnv(os.Args[1])
	ciServerURL := strings.TrimSuffix(getEnv("JENKINS_URL"), "/")
	jwksURL := fmt.Sprintf("%s/oidc/jwks", ciServerURL)
	boundIssuer := fmt.Sprintf("%s/oidc", ciServerURL)
	boundAudience := "https://example.com"

	// fetch the jenkins jwt key set.
	//
	// a key set is public object alike:
	//
	// 		{
	//   		"keys": [
	//     			{
	//     			  	"kid": "oidc-id-token-example",
	//     			  	"kty": "RSA",
	//     			  	"alg": "RS256",
	//     			  	"use": "sig",
	//     			  	"n": "ANxaPnYj7SxFMkbKuljODy2R-4ki4IdIFkxauYppUTkoaBEjZQeVPeQddXO2ifRR8lKT_qesWdU-GQYj-6eIAtfBQlRPwJf-jce0J2jEqYgoqwhdDKkCzZoE6A0D8de8J2P7FZM_gA1d0LEzgbWf3mkQ94wypNVUMxKdHQ2V-nfQgfJzKKXjpkSD5bxrVjd12RGCsCx1Eu_HzuyQFecQFXM4R9guISOdt-uprGtGsawCpYtDPTNYhiu_hX_31xqw3A8mi2rrkEI0tBR7AbJsFl4Y6hjK343A8-v5pxhfaWvhLWyTnG7px0lZg6G8dJFet25iodWX_wOf4qD7092d80M",
	//     			  	"e": "AQAB"
	//     			}
	//   		]
	// 		}
	log.Printf("Getting the Jenkins JWT public key set from the jwks endpoint at %s...", jwksURL)
	keySet, err := jwk.Fetch(context.Background(), jwksURL)
	if err != nil {
		log.Fatalf("failed to parse JWK from %s: %v", jwksURL, err)
	}
	if keySet.Len() < 1 {
		log.Fatalf("%s did not return any key", jwksURL)
	}

	// parse and validate the job id token jwt against the jenkins jwt key set.
	//
	// a job jwt is a private string alike:
	//
	// 		eyJraWQiOiJvaWRjLWlkLXRva2VuLWV4YW1wbGUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2plbmtpbnMuZXhhbXBsZS5jb20vb2lkYyIsImF1ZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJleHAiOjE3NTU4MDQxMDMsImlhdCI6MTc1NTgwMDUwMywic3ViIjoiaHR0cHM6Ly9qZW5raW5zLmV4YW1wbGUuY29tL2pvYi9qZW5raW5zLXZhbGlkYXRlLWp3dC8iLCJidWlsZF9udW1iZXIiOjF9.Ov8XEe2qKSky9ZTQU6KJWxD4-zSTIu9-z7Vfqee6NtWwJyP9DMAEF00Ss_VdQY85M01adrIEytkToHUNKtYnc8uSiYxXY9GFLdeU0KJ8y3V6BFxx3yclJsEwc30ggHvY1ZZLtGSbXqi4xNddouxP5z3gdW-AlPdkldp4Cjmq4vnGbSaMeuV904F3vS4f8EdJsEYRTMUlQ0qQwTJCeu61xTaqUORKB8KKOTBHetR76PmUwgZXoX48YDJzQrXFRVwRu6-SKE8tHbKLj3jxvuDT_aOrKms8SGbgtdkA98mg_YiQKKK1683L1jnRL8yO1jgIQWs6GnIZxC3A6qCQF1BiTA
	//
	// and decoded as a private object is alike:
	//
	// 		header:
	//			{
	//				"kid": "oidc-id-token-example",
	//				"alg": "RS256"
	//			}
	//
	// 		payload:
	//
	//			{
	//				"iss": "https://jenkins.example.com/oidc",
	//				"aud": "https://example.com",
	//				"exp": 1755804103,
	//				"iat": 1755800503,
	//				"sub": "https://jenkins.example.com/job/jenkins-validate-jwt/",
	//				"build_number": 1
	//			}
	//
	//		signature:
	//
	//			the value is the 3rd part of the jwt.
	//
	//			in this particular example the jwt can be validated with:
	//
	//				RSASHA256(
	//   				base64UrlEncode(header) + "." + base64UrlEncode(payload),
	//					jenkinsJwtKeySet.getKey(header.kid))
	log.Println("Validating Jenkins CI job JWT...")
	token, err := jwt.ParseString(ciJobJWT, jwt.WithAudience(boundAudience), jwt.WithIssuer(boundIssuer), jwt.WithKeySet(keySet))
	if err != nil {
		log.Fatalf("failed to validate the jwt: %v", err)
	}

	var jobURL string
	if err = token.Get("sub", &jobURL); err != nil {
		log.Fatalf("failed to get the sub claim from the jwt: %v", err)
	}
	var buildNumber float64
	if err = token.Get("build_number", &buildNumber); err != nil {
		log.Fatalf("failed to get the build_number claim from the jwt: %v", err)
	}
	log.Printf("jwt is valid for the %s/%d job", strings.TrimSuffix(jobURL, "/"), int(buildNumber))

	// dump the jwt claims (sorted by claim name).
	claims := make([]string, 0, len(token.Keys()))
	for _, k := range token.Keys() {
		var v any
		if err = token.Get(k, &v); err != nil {
			log.Fatalf("failed to get the %s claim from the jwt: %v", k, err)
		}
		switch v := v.(type) {
		case string:
			claims = append(claims, fmt.Sprintf("%s=%s", k, v))
		case []string:
			for _, v := range v {
				claims = append(claims, fmt.Sprintf("%s=%s", k, v))
			}
		case time.Time:
			claims = append(claims, fmt.Sprintf("%s=%s", k, v.Format("2006-01-02T15:04:05-0700")))
		case float64:
			claims = append(claims, fmt.Sprintf("%s=%v", k, v))
		default:
			log.Printf("WARNING: skipping the %s claim with type %T value %v", k, v, v)
			continue
		}
	}
	sort.Strings(claims)
	for _, claim := range claims {
		log.Printf("jwt claim: %s", claim)
	}
}
