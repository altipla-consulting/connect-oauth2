package oauth2

import (
	"context"
	"fmt"

	"connectrpc.com/connect/v2"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

// GoogleIDTokenV2 adds a Google ID token to Connect v2 requests.
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
