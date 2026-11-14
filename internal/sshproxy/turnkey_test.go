package sshproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const turnkeyTestOrg = "org-id"

// fakeTurnkey stands in for the Turnkey API. Like the enclave, it signs only
// a userauth request whose session-bind carries a valid host-key signature over
// the same session ID, and it records the host key it verified.
type fakeTurnkey struct {
	t      *testing.T
	apiKey *ecdsa.PrivateKey
	key    ed25519.PrivateKey
	// status is the submitted activity's status; pending activities complete after approveAfter polls.
	status       string
	approveAfter int

	mu        sync.Mutex
	polls     int
	signature string
	hosts     [][]byte
}

func newFakeTurnkey(t *testing.T, status string) (*fakeTurnkey, *TurnkeySigner, ssh.Signer) {
	t.Helper()
	apiKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fake := &fakeTurnkey{t: t, apiKey: apiKey, key: private, status: status}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	scalar, err := apiKey.Bytes()
	require.NoError(t, err)
	signer, err := NewTurnkeySigner(server.URL, turnkeyTestOrg, hex.EncodeToString(scalar))
	require.NoError(t, err)
	signer.PollInterval = 10 * time.Millisecond
	upstreamKey, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	return fake, signer, upstreamKey
}

func (f *fakeTurnkey) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	require.NoError(f.t, err)
	f.verifyStamp(r.Header.Get("X-Stamp"), body)
	f.mu.Lock()
	defer f.mu.Unlock()
	activity := map[string]any{"id": "0f8c2a1e-6b4d-4e5f-9a7b-3c2d1e0f9a8b"}
	switch r.URL.Path {
	case "/public/v1/submit/sign_ssh_userauth":
		var req struct {
			Type           string `json:"type"`
			OrganizationID string `json:"organizationId"`
			Parameters     struct {
				SignWith     string `json:"signWith"`
				UserauthData string `json:"userauthData"`
				SessionBind  string `json:"sessionBind"`
			} `json:"parameters"`
		}
		require.NoError(f.t, json.Unmarshal(body, &req))
		require.Equal(f.t, "ACTIVITY_TYPE_SIGN_SSH_USERAUTH", req.Type)
		require.Equal(f.t, turnkeyTestOrg, req.OrganizationID)
		require.Equal(f.t, "turnkey-key-id", req.Parameters.SignWith)
		data, err := hex.DecodeString(req.Parameters.UserauthData)
		require.NoError(f.t, err)
		bind, err := hex.DecodeString(req.Parameters.SessionBind)
		require.NoError(f.t, err)
		f.hosts = append(f.hosts, verifySessionBind(f.t, data, bind))
		f.signature = hex.EncodeToString(ed25519.Sign(f.key, data))
		activity["status"] = f.status
	case "/public/v1/query/get_activity":
		f.polls++
		activity["status"] = f.status
		if f.approveAfter > 0 && f.polls >= f.approveAfter {
			activity["status"] = "ACTIVITY_STATUS_COMPLETED"
		}
	default:
		http.NotFound(w, r)
		return
	}
	if activity["status"] == "ACTIVITY_STATUS_COMPLETED" {
		activity["result"] = map[string]any{"signSshUserauthResult": map[string]string{"signature": f.signature}}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"activity": activity}) // the client reports a truncated body
}

func (f *fakeTurnkey) verifyStamp(header string, body []byte) {
	raw, err := base64.RawURLEncoding.DecodeString(header)
	require.NoError(f.t, err)
	var stamp struct{ PublicKey, Signature, Scheme string }
	require.NoError(f.t, json.Unmarshal(raw, &stamp))
	require.Equal(f.t, "SIGNATURE_SCHEME_TK_API_P256", stamp.Scheme)
	require.Equal(f.t, compressedP256(&f.apiKey.PublicKey), stamp.PublicKey)
	signature, err := hex.DecodeString(stamp.Signature)
	require.NoError(f.t, err)
	digest := sha256.Sum256(body)
	require.True(f.t, ecdsa.VerifyASN1(&f.apiKey.PublicKey, digest[:], signature), "stamp must sign the exact body")
}

// verifySessionBind checks what the enclave checks and returns the verified host key.
func verifySessionBind(t *testing.T, data, bind []byte) []byte {
	t.Helper()
	var parsed struct {
		HostKey, SessionID, Signature []byte
		Forwarding                    bool
	}
	require.NoError(t, ssh.Unmarshal(bind, &parsed))
	require.False(t, parsed.Forwarding)
	sessionID, _, ok := sshString(data)
	require.True(t, ok)
	require.Equal(t, sessionID, parsed.SessionID, "session-bind must name the userauth session")
	host, err := ssh.ParsePublicKey(parsed.HostKey)
	require.NoError(t, err)
	var signature ssh.Signature
	require.NoError(t, ssh.Unmarshal(parsed.Signature, &signature))
	require.NoError(t, host.Verify(parsed.SessionID, &signature), "host must have signed the session ID")
	return parsed.HostKey
}

func turnkeyGrant(t *testing.T, address string, host, upstreamKey ssh.Signer) *Grant {
	t.Helper()
	g := grant(t, address, host, nil)
	g.PrivateKey = yaml.Node{}
	g.TurnkeyKey = &TurnkeyKey{SignWith: "turnkey-key-id", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(upstreamKey.PublicKey())))}
	return g
}

func ecdsaKey(t *testing.T) ssh.Signer {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	return signer
}

func rsaKey(t *testing.T) ssh.Signer {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	return signer
}

func TestTurnkeyKeySignsUpstreamLogin(t *testing.T) {
	ed25519Host, _ := key(t)
	cases := []struct {
		name string
		host ssh.Signer
	}{
		{"ssh-ed25519 host key", ed25519Host},
		{"ecdsa-sha2-nistp256 host key", ecdsaKey(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientKey, _ := key(t)
			proxyHost, _ := key(t)
			fake, turnkey, upstreamKey := newFakeTurnkey(t, "ACTIVITY_STATUS_COMPLETED")
			g := turnkeyGrant(t, testBackend(t, tc.host, upstreamKey), tc.host, upstreamKey)
			address, audits := serveProxy(t, &Server{HostKey: proxyHost, ClientPublicKey: clientKey.PublicKey(), Authorize: (&recordAuth{g: g}).authorize, Turnkey: turnkey})
			client, err := connect(address, clientKey, proxyHost)
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			session, err := client.NewSession()
			require.NoError(t, err)
			output, err := session.Output("git-upload-pack 'repo'")
			var exit *ssh.ExitError
			require.ErrorAs(t, err, &exit)
			require.Equal(t, "ok:git-upload-pack 'repo'", string(output))

			fake.mu.Lock()
			defer fake.mu.Unlock()
			require.Equal(t, [][]byte{tc.host.PublicKey().Marshal()}, fake.hosts)
			require.Equal(t, transform.ActionContinue, audits.all()[0].Action)
		})
	}
}

func TestTurnkeyApprovalWaitsWithinHandshake(t *testing.T) {
	cases := []struct {
		name         string
		approveAfter int
		wantErr      string
	}{
		{"approved before the deadline", 3, ""},
		{"never approved", 0, "still needs approval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientKey, _ := key(t)
			proxyHost, _ := key(t)
			backendHost, _ := key(t)
			fake, turnkey, upstreamKey := newFakeTurnkey(t, "ACTIVITY_STATUS_CONSENSUS_NEEDED")
			fake.approveAfter = tc.approveAfter
			g := turnkeyGrant(t, testBackend(t, backendHost, upstreamKey), backendHost, upstreamKey)
			address, audits := serveProxy(t, &Server{HostKey: proxyHost, ClientPublicKey: clientKey.PublicKey(), Authorize: (&recordAuth{g: g}).authorize, Turnkey: turnkey, HandshakeTimeout: 500 * time.Millisecond})
			client, err := connect(address, clientKey, proxyHost)
			if tc.wantErr == "" {
				require.NoError(t, err)
				require.NoError(t, client.Close())
				return
			}
			require.Error(t, err)
			require.Eventually(t, func() bool { return len(audits.all()) == 1 }, 5*time.Second, 10*time.Millisecond)
			require.ErrorContains(t, audits.all()[0].Err, "activity 0f8c2a1e-6b4d-4e5f-9a7b-3c2d1e0f9a8b "+tc.wantErr)
		})
	}
}

func TestTurnkeyRefusalsFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		status string
		host   func(*testing.T) ssh.Signer
		server func(*Server)
		reject bool
		errMsg string
	}{
		{name: "policy rejection", status: "ACTIVITY_STATUS_REJECTED", reject: true, errMsg: "turnkey denied the signature"},
		{name: "failed activity", status: "ACTIVITY_STATUS_FAILED", errMsg: "turnkey signing activity failed"},
		{name: "unsupported host key", status: "ACTIVITY_STATUS_COMPLETED", host: rsaKey, errMsg: "requires an ssh-ed25519 or ecdsa-sha2-nistp256 host key"},
		{name: "signing not configured", status: "ACTIVITY_STATUS_COMPLETED", server: func(s *Server) { s.Turnkey = nil }, errMsg: "turnkey signing not configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientKey, _ := key(t)
			proxyHost, _ := key(t)
			backendHost, _ := key(t)
			if tc.host != nil {
				backendHost = tc.host(t)
			}
			_, turnkey, upstreamKey := newFakeTurnkey(t, tc.status)
			g := turnkeyGrant(t, testBackend(t, backendHost, upstreamKey), backendHost, upstreamKey)
			server := &Server{HostKey: proxyHost, ClientPublicKey: clientKey.PublicKey(), Authorize: (&recordAuth{g: g}).authorize, Turnkey: turnkey}
			if tc.server != nil {
				tc.server(server)
			}
			address, audits := serveProxy(t, server)
			_, err := connect(address, clientKey, proxyHost)
			require.Error(t, err)
			require.Eventually(t, func() bool { return len(audits.all()) == 1 }, 5*time.Second, 10*time.Millisecond)
			event := audits.all()[0]
			if tc.reject {
				require.Equal(t, transform.ActionReject, event.Action)
				require.Contains(t, event.RequestTransforms[0].Annotations["reason"], tc.errMsg)
			} else {
				require.ErrorContains(t, event.Err, tc.errMsg)
			}
		})
	}
}

func TestTurnkeyErrorsDoNotLeakResponses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		errIs  error
		errMsg string
	}{
		{"redirect is not followed", http.StatusFound, nil, "status 302"},
		{"forbidden is a denial", http.StatusForbidden, errAccessDenied, "turnkey denied the signature"},
		{"server error", http.StatusInternalServerError, nil, "status 500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var followed bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/elsewhere" {
					followed = true
				}
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("upstream-secret-detail")) // the client reports only the status
			}))
			defer server.Close()
			apiKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			scalar, err := apiKey.Bytes()
			require.NoError(t, err)
			signer, err := NewTurnkeySigner(server.URL, turnkeyTestOrg, hex.EncodeToString(scalar))
			require.NoError(t, err)
			_, err = signer.signUserauth(context.Background(), "turnkey-key-id", []byte("data"), []byte("bind"))
			require.ErrorContains(t, err, tc.errMsg)
			require.NotContains(t, err.Error(), "upstream-secret-detail")
			if tc.errIs != nil {
				require.True(t, errors.Is(err, tc.errIs))
			}
			require.False(t, followed)
		})
	}
}

func TestKexRecorderFailsClosed(t *testing.T) {
	packet := func(payload []byte) []byte {
		padding := 4
		out := make([]byte, 5, 5+len(payload)+padding)
		length := uint32(1 + len(payload) + padding)
		out[0], out[1], out[2], out[3], out[4] = byte(length>>24), byte(length>>16), byte(length>>8), byte(length), byte(padding)
		return append(append(out, payload...), make([]byte, padding)...)
	}
	reply := append([]byte{msgKexReply}, ssh.Marshal(struct{ A, B, C []byte }{[]byte("host"), []byte("value"), []byte("sig")})...)
	cases := []struct {
		name   string
		stream []byte
		proof  *kexProof
	}{
		{"reply then NEWKEYS", bytes.Join([][]byte{[]byte("banner\r\nSSH-2.0-test\r\n"), packet(reply), packet([]byte{msgNewKeys})}, nil), &kexProof{hostKey: []byte("host"), signature: []byte("sig")}},
		{"NEWKEYS without reply", append([]byte("SSH-2.0-test\r\n"), packet([]byte{msgNewKeys})...), nil},
		{"reply without NEWKEYS", append([]byte("SSH-2.0-test\r\n"), packet(reply)...), nil},
		{"malformed reply", bytes.Join([][]byte{[]byte("SSH-2.0-test\r\n"), packet([]byte{msgKexReply, 0, 0, 0, 9}), packet([]byte{msgNewKeys})}, nil), nil},
		{"oversized packet", append([]byte("SSH-2.0-test\r\n"), 0x7f, 0, 0, 0, 4), nil},
		{"unterminated banner", bytes.Repeat([]byte("x"), maxBannerBytes+1), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &kexRecorder{}
			// Feed one byte at a time to exercise reassembly across reads.
			for i := range tc.stream {
				r.observe(tc.stream[i : i+1])
			}
			proof, err := r.result()
			if tc.proof == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.proof, proof)
		})
	}
}
