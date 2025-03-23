package oauth2

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"connectrpc.com/connect"
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
func GoogleIDToken(isProduction bool, scope string) connect.Interceptor {
	var ts oauth2.TokenSource
	var initErr error
	if isProduction {
		ts, initErr = idtoken.NewTokenSource(context.Background(), scope)
	} else {
		ts = oauth2.ReuseTokenSource(nil, new(localTokenSource))
	}

	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if initErr != nil {
				return nil, fmt.Errorf("connect-oauth2: cannot initialize token source: %w", initErr)
			}

			if ts == nil {
				return next(ctx, req)
			}

			token, err := ts.Token()
			if err != nil {
				return nil, fmt.Errorf("connect-oauth2: cannot retrieve token: %w", err)
			}
			req.Header().Set("Authorization", "Bearer "+token.AccessToken)
			return next(ctx, req)
		})
	})
}
