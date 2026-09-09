package config

import "testing"

// The historical constants are the same on every install, so the tunnel's own
// subnet identifies the software. Per-install values must reach the TUN inbound,
// and an absent value must still yield a working tunnel.
func TestTunAddressPerInstall(t *testing.T) {
	cases := []struct {
		name   string
		v4, v6 string
		wantV4 string
		wantV6 string
	}{
		{"absent falls back to the historical constants", "", "", "172.19.0.1/28", "fdfe:dcba:9876::1/126"},
		{"per-install values are used", "172.28.14.33/28", "fd7a:1c2b:3d4e:5f60::1/126", "172.28.14.33/28", "fd7a:1c2b:3d4e:5f60::1/126"},
		{"unparseable falls back rather than breaking the tunnel", "not-an-address", "also-bad", "172.19.0.1/28", "fdfe:dcba:9876::1/126"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got4 := tunPrefixOrDefault(tc.v4, "172.19.0.1/28").String()
			got6 := tunPrefixOrDefault(tc.v6, "fdfe:dcba:9876::1/126").String()
			if got4 != tc.wantV4 {
				t.Errorf("v4 = %s, want %s", got4, tc.wantV4)
			}
			if got6 != tc.wantV6 {
				t.Errorf("v6 = %s, want %s", got6, tc.wantV6)
			}
		})
	}
}
