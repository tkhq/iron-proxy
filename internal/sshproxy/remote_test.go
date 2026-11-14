package sshproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// stubRemoteSigner holds the key locally and records every request, standing
// in for any RemoteSigner implementation.
type stubRemoteSigner struct {
	key        ssh.Signer
	algorithms []string
	err        error

	mu       sync.Mutex
	requests []UserauthRequest
}

func (s *stubRemoteSigner) HostKeyAlgorithms() []string { return s.algorithms }

func (s *stubRemoteSigner) SignUserauth(_ context.Context, req UserauthRequest) (*ssh.Signature, error) {
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return s.key.Sign(rand.Reader, req.Data)
}

// remoteGrant reaches address with the remote key upstreamKey.
func remoteGrant(t *testing.T, address string, host, upstreamKey ssh.Signer) *Grant {
	t.Helper()
	g := grant(t, address, host, nil)
	g.PrivateKey = yaml.Node{}
	g.RemoteKey = &RemoteKey{KeyID: "turnkey-key-id", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(upstreamKey.PublicKey())))}
	return g
}

func TestRemoteSignerContract(t *testing.T) {
	ecdsaHost := ecdsaKey(t)
	wrongKey, _ := key(t)
	cases := []struct {
		name       string
		host       ssh.Signer
		algorithms []string
		signWith   func(upstream ssh.Signer) ssh.Signer
		err        error
		reject     bool
		errMsg     string
	}{
		{name: "signs with the session-bind", host: ecdsaHost, algorithms: []string{ssh.KeyAlgoECDSA256}},
		{name: "policy denial is a rejection", host: ecdsaHost, algorithms: []string{ssh.KeyAlgoECDSA256}, err: ErrSignatureDenied, reject: true, errMsg: "remote signer denied the signature"},
		{name: "operational error", host: ecdsaHost, algorithms: []string{ssh.KeyAlgoECDSA256}, err: errors.New("signer unavailable"), errMsg: "signer unavailable"},
		{name: "unsupported host key type", host: ecdsaHost, algorithms: []string{ssh.KeyAlgoED25519}, errMsg: "remote signer does not support ecdsa-sha2-nistp256 host keys"},
		{name: "signature from another key", host: ecdsaHost, algorithms: []string{ssh.KeyAlgoECDSA256}, signWith: func(ssh.Signer) ssh.Signer { return wrongKey }, errMsg: "does not match the granted public key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientKey, _ := key(t)
			proxyHost, _ := key(t)
			upstreamKey, _ := key(t)
			remote := &stubRemoteSigner{key: upstreamKey, algorithms: tc.algorithms, err: tc.err}
			if tc.signWith != nil {
				remote.key = tc.signWith(upstreamKey)
			}
			g := remoteGrant(t, testBackend(t, tc.host, upstreamKey), tc.host, upstreamKey)
			address, audits := serveProxy(t, &Server{HostKey: proxyHost, ClientPublicKey: clientKey.PublicKey(), Authorize: (&recordAuth{g: g}).authorize, RemoteSigner: remote})
			client, err := connect(address, clientKey, proxyHost)
			if tc.errMsg == "" {
				require.NoError(t, err)
				require.NoError(t, client.Close())
				remote.mu.Lock()
				defer remote.mu.Unlock()
				require.Len(t, remote.requests, 1)
				req := remote.requests[0]
				require.Equal(t, "turnkey-key-id", req.KeyID)
				require.Equal(t, upstreamKey.PublicKey().Marshal(), req.PublicKey.Marshal())
				require.Equal(t, tc.host.PublicKey().Marshal(), req.HostKey.Marshal())
				require.Equal(t, tc.host.PublicKey().Marshal(), verifySessionBind(t, req.Data, req.SessionBind))
				return
			}
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

func TestBuildRemoteSigner(t *testing.T) {
	apiKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	scalar, err := apiKey.Bytes()
	require.NoError(t, err)
	t.Setenv("SSH_REMOTE_SIGNER_TEST_KEY", hex.EncodeToString(scalar))
	t.Setenv("SSH_REMOTE_SIGNER_EMPTY_KEY", "")
	cases := []struct {
		name   string
		config map[string]string
		errMsg string
	}{
		{"turnkey", map[string]string{"type": "turnkey", "organization_id": "org", "api_private_key_env": "SSH_REMOTE_SIGNER_TEST_KEY"}, ""},
		{"turnkey without organization", map[string]string{"type": "turnkey", "api_private_key_env": "SSH_REMOTE_SIGNER_TEST_KEY"}, "organization_id required"},
		{"turnkey without API key", map[string]string{"type": "turnkey", "organization_id": "org", "api_private_key_env": "SSH_REMOTE_SIGNER_EMPTY_KEY"}, "invalid turnkey API private key"},
		{"unknown type", map[string]string{"type": "other"}, "unknown SSH remote signer type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.config)
			require.NoError(t, err)
			var node yaml.Node
			require.NoError(t, yaml.Unmarshal(data, &node))
			signer, err := BuildRemoteSigner(*node.Content[0], slog.New(slog.NewJSONHandler(io.Discard, nil)))
			if tc.errMsg != "" {
				require.ErrorContains(t, err, tc.errMsg)
				require.NotContains(t, err.Error(), hex.EncodeToString(scalar))
				return
			}
			require.NoError(t, err)
			require.Equal(t, []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256}, signer.HostKeyAlgorithms())
		})
	}
}
