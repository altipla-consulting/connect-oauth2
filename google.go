package oauth2

import (
	"context"
	"fmt"
	"os/exec"

	"connectrpc.com/connect"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

// GoogleIDToken adds an ID token as a bearer header to the requests. It needs to check for production environments to
// avoid trying to generate an id token in the local computer where it's not available.
func GoogleIDToken(isProduction bool, scope string) connect.Interceptor {
	var ts oauth2.TokenSource
	var initErr error
	if isProduction {
		ts, initErr = idtoken.NewTokenSource(context.Background(), scope)
	} else {
		cmd := exec.Command("gcloud", "auth", "print-identity-token")
		output, err := cmd.Output()
		if err != nil {
			initErr = fmt.Errorf("connect-oauth2: cannot retrieve local user token: %w", err)
		} else {
			ts = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: string(output)})
		}
	}

	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if initErr != nil {
				return nil, fmt.Errorf("connect-oauth2: cannot initialize token source: %w", initErr)
			}

			if !isProduction {
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
