package tunnelservice

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

// The tunnel service runs elevated and can start, stop and reconfigure the
// system-wide TUN device, but it is reached over a plain loopback gRPC socket.
// Without this gate any local process could drive it.
//
// The token is minted by the service at startup and written next to the
// executable with owner-only permissions; the commander reads it back. This
// stops unprivileged and drive-by callers. It does NOT stop malware already
// running as the same user that owns the token file - that needs OS-level peer
// authentication (named pipes with ACLs on Windows, SO_PEERCRED on Linux),
// which would be a larger change to the transport itself.
const tokenHeader = "x-hiddify-tunnel-token"

const tokenFileName = "tunnel-service.token"

var (
	tokenOnce  sync.Once
	tokenValue string
)

func tokenPath() string {
	return filepath.Join(getCurrentExecutableDirectory(), tokenFileName)
}

// issueToken mints a fresh token and persists it for the commander to read.
// Called by the service side at startup.
func issueToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	// 0600: only the account running the service may read it back.
	if err := os.WriteFile(tokenPath(), []byte(token), 0o600); err != nil {
		return "", err
	}
	tokenOnce.Do(func() {})
	tokenValue = token
	return token, nil
}

// readToken loads the token the running service issued. Called by the commander.
func readToken() string {
	data, err := os.ReadFile(tokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// authUnaryInterceptor rejects any call that does not carry the current token.
func authUnaryInterceptor(expected string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		values := md.Get(tokenHeader)
		if len(values) != 1 {
			return nil, status.Error(codes.Unauthenticated, "missing tunnel service token")
		}
		// Constant time: the token is a bearer credential.
		if subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid tunnel service token")
		}
		return handler(ctx, req)
	}
}

// withToken attaches the token to an outgoing call.
func withToken(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, tokenHeader, readToken())
}
