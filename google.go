package oauth2

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

var _ oauth2.TokenSource = (*localTokenSource)(nil)

type localTokenSource struct{}

func (l *localTokenSource) Token() (*oauth2.Token, error) {
	cmd := exec.Command("gcloud", "auth", "print-identity-token")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("connect-oauth2: cannot retrieve local user token: %w", err)
	}
	return &oauth2.Token{
		AccessToken: strings.TrimSpace(string(output)),
		Expiry:      time.Now().Add(time.Minute * 50),
	}, nil
}

// GoogleIDToken adds an ID token as a bearer header to the requests. It needs to check for production environments to
// avoid trying to generate an id token in the local computer where it's not available.
func GoogleIDTokenV2(isProduction bool, scope string) connect.ClientInterceptor {
	var ts oauth2.TokenSource
	var initErr error
	if isProduction {
		ts, initErr = idtoken.NewTokenSource(context.Background(), scope)
	} else {
		ts = oauth2.ReuseTokenSource(nil, new(localTokenSource))
	}
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			if initErr != nil {
				return nil, fmt.Errorf("connect-oauth2: cannot initialize token source: %w", initErr)
			}
			token, err := ts.Token()
			if err != nil {
				return nil, fmt.Errorf("connect-oauth2: cannot retrieve token: %w", err)
			}
			info, ok := connect.CallInfoForClientContext(ctx)
			if !ok {
				return nil, fmt.Errorf("connect-oauth2: missing client call info")
			}
			info.RequestHeader().Set("Authorization", "Bearer "+token.AccessToken)
			return next(ctx, spec)
		}
	}
}
