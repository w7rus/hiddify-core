package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

// Verifies the mixed inbound's Users list: the app credential, the LAN sharing
// user, both, or neither.
func TestSetInboundMixedUsers(t *testing.T) {
	type want struct{ username, password string }
	cases := []struct {
		name  string
		mutOp func(*HiddifyOptions)
		want  []want
	}{
		{
			name:  "no credentials leaves the inbound open",
			mutOp: func(h *HiddifyOptions) {},
			want:  nil,
		},
		{
			name: "app credentials only",
			mutOp: func(h *HiddifyOptions) {
				h.MixedUsername, h.MixedPassword = "appuser", "apppass"
			},
			want: []want{{"appuser", "apppass"}},
		},
		{
			name: "lan password is ignored while lan sharing is off",
			mutOp: func(h *HiddifyOptions) {
				h.LanSharingPassword = "lanpass"
			},
			want: nil,
		},
		{
			name: "app credentials plus lan sharing user",
			mutOp: func(h *HiddifyOptions) {
				h.MixedUsername, h.MixedPassword = "appuser", "apppass"
				h.AllowConnectionFromLAN = true
				h.LanSharingPassword = "lanpass"
			},
			want: []want{{"appuser", "apppass"}, {"hiddify", "lanpass"}},
		},
		{
			name: "half a credential is not a credential",
			mutOp: func(h *HiddifyOptions) { h.MixedUsername = "appuser" },
			want:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hopt := &HiddifyOptions{}
			hopt.MixedPort = 51234
			tc.mutOp(hopt)

			opts := &option.Options{}
			setInbound(opts, hopt)

			var mixed *option.HTTPMixedInboundOptions
			for _, in := range opts.Inbounds {
				if m, ok := in.Options.(*option.HTTPMixedInboundOptions); ok {
					mixed = m
					break
				}
			}
			if mixed == nil {
				t.Fatal("no mixed inbound was produced")
			}
			if mixed.ListenPort != 51234 {
				t.Errorf("listen port = %d, want 51234", mixed.ListenPort)
			}
			if len(mixed.Users) != len(tc.want) {
				t.Fatalf("got %d users %+v, want %d", len(mixed.Users), mixed.Users, len(tc.want))
			}
			for i, w := range tc.want {
				if mixed.Users[i].Username != w.username || mixed.Users[i].Password != w.password {
					t.Errorf("user[%d] = %q/%q, want %q/%q", i,
						mixed.Users[i].Username, mixed.Users[i].Password, w.username, w.password)
				}
			}
		})
	}
}
