package hcore

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Guards the gate on the Core service: it can enumerate servers, stream logs and
// reroute traffic, so an edit that lets an unauthenticated call through must fail
// loudly here.
func TestAuthorizeGrpc(t *testing.T) {
	const secret = "s3cr3t-token"
	const coreMethod = "/hcore.Core/OutboundsInfo"
	const helloMethod = "/hello.Hello/SayHello"

	withMD := func(pairs ...string) context.Context {
		return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
	}

	cases := []struct {
		name    string
		stored  string
		ctx     context.Context
		method  string
		wantErr codes.Code // codes.OK means the call must be allowed
	}{
		{"no token established allows calls", "", context.Background(), coreMethod, codes.OK},
		{"hello stays reachable as a liveness probe", secret, context.Background(), helloMethod, codes.OK},
		{"core call without metadata is rejected", secret, context.Background(), coreMethod, codes.Unauthenticated},
		{"core call without the header is rejected", secret, withMD("other", "x"), coreMethod, codes.Unauthenticated},
		{"wrong token is rejected", secret, withMD(grpcTokenHeader, "nope"), coreMethod, codes.Unauthenticated},
		{"correct token is accepted", secret, withMD(grpcTokenHeader, secret), coreMethod, codes.OK},
		{"empty token value is rejected", secret, withMD(grpcTokenHeader, ""), coreMethod, codes.Unauthenticated},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grpcSecretMu.Lock()
			grpcSecret = tc.stored
			grpcSecretMu.Unlock()

			err := authorizeGrpc(tc.ctx, tc.method)
			if tc.wantErr == codes.OK {
				if err != nil {
					t.Fatalf("expected the call to be allowed, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected the call to be rejected, but it was allowed")
			}
			if got := status.Code(err); got != tc.wantErr {
				t.Fatalf("code = %v, want %v", got, tc.wantErr)
			}
		})
	}
}

// Two tokens differing only in length must not be accepted for one another.
func TestAuthorizeGrpcRejectsPrefix(t *testing.T) {
	grpcSecretMu.Lock()
	grpcSecret = "abcdef"
	grpcSecretMu.Unlock()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(grpcTokenHeader, "abc"))
	if err := authorizeGrpc(ctx, "/hcore.Core/Stop"); err == nil {
		t.Fatal("a prefix of the token was accepted")
	}
}
