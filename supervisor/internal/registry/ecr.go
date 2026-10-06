package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/go-containerregistry/pkg/authn"
)

// ecrLogins caches the login ECR handed out per registry host (good for
// twelve hours).
var ecrLogins = struct {
	sync.Mutex
	m map[string]ecrLogin_
}{m: map[string]ecrLogin_{}}

type ecrLogin_ struct {
	user, pass string
	until      time.Time
}

// ecrLogin turns a console-supplied AWS credential into a registry login for
// host: static keys (with an optional session token), optionally exchanged
// for role credentials first, then ECR GetAuthorizationToken.
func ecrLogin(ctx context.Context, a Auth, host string) (authn.Authenticator, error) {
	ecrLogins.Lock()
	if l, ok := ecrLogins.m[host]; ok && time.Now().Before(l.until) {
		ecrLogins.Unlock()
		return authn.FromConfig(authn.AuthConfig{Username: l.user, Password: l.pass}), nil
	}
	ecrLogins.Unlock()

	region := a.Region
	if region == "" {
		region = ecrRegion(host)
	}
	if region == "" {
		return nil, fmt.Errorf("ecr credential for %s: region unknown (not an ECR host; set region on the credential)", host)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var provider aws.CredentialsProvider = credentials.NewStaticCredentialsProvider(a.Username, a.Secret, a.SessionToken)
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region), awsconfig.WithCredentialsProvider(provider))
	if err != nil {
		return nil, fmt.Errorf("ecr credential for %s: %w", host, err)
	}
	if a.RoleARN != "" {
		cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), a.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "fleetwide-supervisor"
		}))
	}
	out, err := ecr.NewFromConfig(cfg).GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("ecr login for %s: %w", host, err)
	}
	if len(out.AuthorizationData) == 0 || out.AuthorizationData[0].AuthorizationToken == nil {
		return nil, errors.New("ecr login: empty authorization data")
	}
	user, pass, err := decodeECRToken(*out.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return nil, err
	}
	until := time.Now().Add(11 * time.Hour)
	if out.AuthorizationData[0].ExpiresAt != nil {
		until = out.AuthorizationData[0].ExpiresAt.Add(-10 * time.Minute)
	}
	ecrLogins.Lock()
	ecrLogins.m[host] = ecrLogin_{user: user, pass: pass, until: until}
	ecrLogins.Unlock()
	return authn.FromConfig(authn.AuthConfig{Username: user, Password: pass}), nil
}

// decodeECRToken splits the base64 "AWS:<password>" ECR hands out.
func decodeECRToken(tok string) (user, pass string, err error) {
	b, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		return "", "", fmt.Errorf("ecr token: %w", err)
	}
	user, pass, ok := strings.Cut(string(b), ":")
	if !ok || user == "" || pass == "" {
		return "", "", errors.New("ecr token: not user:password")
	}
	return user, pass, nil
}

// ecrRegion reads the region out of an ECR host
// (<account>.dkr.ecr.<region>.amazonaws.com[.cn]).
func ecrRegion(host string) string {
	m := ecrPrivateRE.FindStringSubmatch(host)
	if m == nil {
		return ""
	}
	parts := strings.Split(host, ".")
	for i, p := range parts {
		if (p == "ecr" || p == "ecr-fips") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
