package sshproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// RemoteKey names an upstream key held by the configured RemoteSigner, in
// place of a private_key source. The proxy never sees the private key.
type RemoteKey struct {
	// KeyID is the signer's identifier for the key.
	KeyID string `json:"key_id" yaml:"key_id"`
	// PublicKey is the key's public half in authorized-key format.
	PublicKey string `json:"public_key" yaml:"public_key"`
}

// UserauthRequest is one upstream public key login to sign. SessionBind lets
// the signer verify the destination itself instead of trusting the proxy.
type UserauthRequest struct {
	// KeyID and PublicKey come from the grant's remote_key.
	KeyID     string
	PublicKey ssh.PublicKey
	// Data is the RFC 4252 section 7 data the signature covers. It starts with the session ID.
	Data []byte
	// SessionBind is the contents of a session-bind@openssh.com agent extension
	// (OpenSSH PROTOCOL.agent) after the extension name: the server host key,
	// the session ID, the host key's signature over it, and is_forwarding=false.
	SessionBind []byte
	// HostKey is the server host key the proxy pinned and the bind names.
	HostKey ssh.PublicKey
}

// RemoteSigner signs upstream SSH logins with keys it holds. Implementations
// should verify SessionBind and authorize the host key, user, and service
// before signing. A signature is bound to one session; implementations must
// not cache or replay it.
type RemoteSigner interface {
	// HostKeyAlgorithms lists the host key types whose session-bind the signer verifies.
	HostKeyAlgorithms() []string
	// SignUserauth returns a signature over req.Data, waiting no longer than ctx.
	// Return an error wrapping ErrSignatureDenied for policy denials.
	SignUserauth(ctx context.Context, req UserauthRequest) (*ssh.Signature, error)
}

// ErrSignatureDenied marks a remote signer's policy denial; it is audited as a rejection.
var ErrSignatureDenied = fmt.Errorf("%w: remote signer denied the signature", errAccessDenied)

// BuildRemoteSigner builds the signer an ssh.remote_signer block selects by type.
func BuildRemoteSigner(node yaml.Node, _ *slog.Logger) (RemoteSigner, error) {
	var kind struct {
		Type string `yaml:"type"`
	}
	if node.Decode(&kind) != nil {
		return nil, errors.New("invalid SSH remote signer configuration")
	}
	switch kind.Type {
	case "turnkey":
		return buildTurnkeySigner(node)
	default:
		return nil, errors.New("unknown SSH remote signer type")
	}
}

// hostProofKeyExchanges are the key exchanges whose message 31 is the
// server's reply (string host key, string server value, string signature over
// the exchange hash), which kexRecorder records for the session-bind. Group
// exchange is excluded because its message 31 carries the group instead.
var hostProofKeyExchanges = []string{
	ssh.KeyExchangeMLKEM768X25519,
	ssh.KeyExchangeCurve25519,
	"curve25519-sha256@libssh.org",
	ssh.KeyExchangeECDHP256,
	ssh.KeyExchangeECDHP384,
	ssh.KeyExchangeECDHP521,
}

// remoteHostKeyAlgorithms narrows the host key algorithms a grant negotiates
// to those the signer verifies; pinned is nil for TLS-identity grants.
func remoteHostKeyAlgorithms(signer RemoteSigner, pinned ssh.PublicKey) ([]string, error) {
	supported := signer.HostKeyAlgorithms()
	if pinned == nil {
		return supported, nil
	}
	if !slices.Contains(supported, pinned.Type()) {
		return nil, fmt.Errorf("remote signer does not support %s host keys", pinned.Type())
	}
	return []string{pinned.Type()}, nil
}

// remoteUserauthSigner adapts a RemoteSigner to ssh.Signer for one upstream
// connection, attaching the session-bind recorded from that connection.
type remoteUserauthSigner struct {
	ctx    context.Context
	remote RemoteSigner
	keyID  string
	public ssh.PublicKey
	kex    *kexRecorder
	host   func() ssh.PublicKey
}

func newRemoteUserauthSigner(ctx context.Context, remote RemoteSigner, key RemoteKey, kex *kexRecorder, host func() ssh.PublicKey) (*remoteUserauthSigner, error) {
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
	if err != nil || key.KeyID == "" {
		return nil, errors.New("invalid SSH remote key")
	}
	return &remoteUserauthSigner{ctx: ctx, remote: remote, keyID: key.KeyID, public: public, kex: kex, host: host}, nil
}

func (s *remoteUserauthSigner) PublicKey() ssh.PublicKey { return s.public }

func (s *remoteUserauthSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	// RFC 4252 section 7: the signed data starts with the session identifier.
	sessionID, _, ok := sshString(data)
	if !ok {
		return nil, errors.New("SSH userauth data malformed")
	}
	proof, err := s.kex.result()
	if err != nil {
		return nil, err
	}
	// The recorded reply must be from the key the host key callback accepted.
	host := s.host()
	if host == nil || !bytes.Equal(host.Marshal(), proof.hostKey) {
		return nil, errors.New("SSH host proof does not match the verified host key")
	}
	signature, err := s.remote.SignUserauth(s.ctx, UserauthRequest{
		KeyID:       s.keyID,
		PublicKey:   s.public,
		Data:        data,
		SessionBind: sessionBind(proof, sessionID),
		HostKey:     host,
	})
	if err != nil {
		return nil, err
	}
	// Catch a key mismatch locally rather than as an opaque upstream login failure.
	if s.public.Verify(data, signature) != nil {
		return nil, errors.New("remote signature does not match the granted public key")
	}
	return signature, nil
}
