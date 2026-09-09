package hcore

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The desktop and mobile clients both drive the core over a plain loopback gRPC
// socket (SetupMode 3, GRPC_NORMAL_INSECURE). The Core service can enumerate the
// configured servers, stream logs, switch outbounds and rewrite settings, so an
// unauthenticated socket lets any local process read the user's configuration and
// reroute their traffic.
//
// SetupRequest already carried a Secret that nothing consumed. It is now the
// bearer token for every Core call. The resolved value is written to the working
// directory with 0600 so a client that finds the core already running - a desktop
// core outlives the app - can pick the same token up instead of being locked out.
//
// Limit worth stating plainly: a process running as the same user can read that
// file. This closes drive-by access from other apps, which is the threat here; it
// is not a defence against malware already running as the user. Mode 1/2 mTLS
// remains the stronger option where the client can be given a certificate.
const (
	grpcTokenHeader   = "x-hiddify-core-token"
	grpcTokenFileName = "grpc.token"
)

var (
	grpcSecretMu sync.RWMutex
	grpcSecret   string
)

func grpcTokenPath() string {
	return filepath.Join(sWorkingPath, grpcTokenFileName)
}

// resolveGrpcSecret settles the token for this core: the caller's if it supplied
// one, otherwise whatever a previous run persisted, otherwise a fresh one.
func resolveGrpcSecret(requested string) string {
	grpcSecretMu.Lock()
	defer grpcSecretMu.Unlock()

	token := strings.TrimSpace(requested)
	if token == "" {
		if data, err := os.ReadFile(grpcTokenPath()); err == nil {
			token = strings.TrimSpace(string(data))
		}
	}
	if token == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			// Refuse to fall back to an empty token: that would silently restore
			// the unauthenticated behaviour this exists to remove.
			panic("hcore: unable to generate gRPC token: " + err.Error())
		}
		token = base64.RawURLEncoding.EncodeToString(buf)
	}
	// Best effort: if this fails the client simply cannot discover the token.
	_ = os.WriteFile(grpcTokenPath(), []byte(token), 0o600)
	grpcSecret = token
	return token
}

func currentGrpcSecret() string {
	grpcSecretMu.RLock()
	defer grpcSecretMu.RUnlock()
	return grpcSecret
}

// authorizeGrpc allows the call when no token has been established yet (so a core
// built before this change, or one whose Setup has not run, keeps working) and
// otherwise requires an exact match.
func authorizeGrpc(ctx context.Context, fullMethod string) error {
	expected := currentGrpcSecret()
	if expected == "" {
		return nil
	}
	// Hello is a liveness probe used to decide whether a core is already running,
	// before the client has read the token. It carries no data.
	if strings.HasPrefix(fullMethod, "/hello.") {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get(grpcTokenHeader)
	if len(values) != 1 {
		return status.Error(codes.Unauthenticated, "missing core token")
	}
	if subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid core token")
	}
	return nil
}

func grpcAuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := authorizeGrpc(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func grpcAuthStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := authorizeGrpc(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
