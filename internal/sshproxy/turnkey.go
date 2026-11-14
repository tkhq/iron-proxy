package sshproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultTurnkeyBaseURL       = "https://api.turnkey.com"
	defaultTurnkeyAPIKeyEnv     = "TURNKEY_API_PRIVATE_KEY"
	turnkeyApprovalPollInterval = time.Second
)

// TurnkeyKey names a Turnkey-held Ed25519 key that signs upstream logins in
// place of a private_key source. The key never leaves Turnkey.
type TurnkeyKey struct {
	// SignWith is the Turnkey private key ID or address.
	SignWith string `json:"sign_with" yaml:"sign_with"`
	// PublicKey is the key's ssh-ed25519 public key in authorized-key format.
	PublicKey string `json:"public_key" yaml:"public_key"`
}

// TurnkeySigner submits ACTIVITY_TYPE_SIGN_SSH_USERAUTH activities with a
// proxy-only API key. Turnkey verifies the login request and the server's
// host-key signature over the session before policy evaluates the user,
// service, and host key fingerprint.
type TurnkeySigner struct {
	BaseURL        string
	OrganizationID string
	APIKey         *ecdsa.PrivateKey
	Client         *http.Client
	// PollInterval paces approval polling; 0 means one second.
	PollInterval time.Duration
}

// NewTurnkeySigner builds a signer from a hex-encoded P-256 Turnkey API private key.
func NewTurnkeySigner(baseURL, organizationID, apiPrivateKey string) (*TurnkeySigner, error) {
	if organizationID == "" {
		return nil, errors.New("turnkey organization_id required")
	}
	scalar, err := hex.DecodeString(apiPrivateKey)
	if err != nil || len(scalar) != 32 {
		return nil, errors.New("invalid turnkey API private key")
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	clear(scalar)
	if err != nil {
		return nil, errors.New("invalid turnkey API private key")
	}
	if baseURL == "" {
		baseURL = defaultTurnkeyBaseURL
	}
	return &TurnkeySigner{
		BaseURL:        baseURL,
		OrganizationID: organizationID,
		APIKey:         key,
		Client: &http.Client{
			Timeout: 5 * time.Second,
			// A redirect would forward a stamped request to another target.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// signer returns an ssh.Signer for key. It signs only userauth requests from
// the connection recorded by kex, waiting for approval no longer than ctx.
func (t *TurnkeySigner) signer(ctx context.Context, key TurnkeyKey, kex *kexRecorder, host func() ssh.PublicKey) (ssh.Signer, error) {
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
	if err != nil || public.Type() != ssh.KeyAlgoED25519 || key.SignWith == "" {
		return nil, errors.New("invalid turnkey SSH key")
	}
	return &turnkeyUserauthSigner{ctx: ctx, turnkey: t, key: key, public: public, kex: kex, host: host}, nil
}

type turnkeyUserauthSigner struct {
	ctx     context.Context
	turnkey *TurnkeySigner
	key     TurnkeyKey
	public  ssh.PublicKey
	kex     *kexRecorder
	host    func() ssh.PublicKey
}

func (s *turnkeyUserauthSigner) PublicKey() ssh.PublicKey { return s.public }

func (s *turnkeyUserauthSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
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
	signature, err := s.turnkey.signUserauth(s.ctx, s.key.SignWith, data, sessionBind(proof, sessionID))
	if err != nil {
		return nil, err
	}
	result := &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: signature}
	// Catch a key mismatch locally rather than as an opaque upstream login failure.
	if s.public.Verify(data, result) != nil {
		return nil, errors.New("turnkey signature does not match the granted public key")
	}
	return result, nil
}

type turnkeyActivity struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Result struct {
		SignSSHUserauthResult *struct {
			Signature string `json:"signature"`
		} `json:"signSshUserauthResult"`
	} `json:"result"`
}

// errTurnkeyDenied wraps errAccessDenied so audits record policy denials as rejections.
var errTurnkeyDenied = fmt.Errorf("%w: turnkey denied the signature", errAccessDenied)

var turnkeyActivityIDPattern = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)

// signUserauth submits one activity and, if it needs approval, polls it until
// ctx ends. A signature is bound to one session, so it is never cached or retried
// on another connection.
func (t *TurnkeySigner) signUserauth(ctx context.Context, signWith string, userauthData, bind []byte) ([]byte, error) {
	activity, err := t.post(ctx, "/public/v1/submit/sign_ssh_userauth", map[string]any{
		"type":           "ACTIVITY_TYPE_SIGN_SSH_USERAUTH",
		"timestampMs":    strconv.FormatInt(time.Now().UnixMilli(), 10),
		"organizationId": t.OrganizationID,
		"parameters": map[string]string{
			"signWith":     signWith,
			"userauthData": hex.EncodeToString(userauthData),
			"sessionBind":  hex.EncodeToString(bind),
		},
	})
	if err != nil {
		return nil, err
	}
	interval := t.PollInterval
	if interval == 0 {
		interval = turnkeyApprovalPollInterval
	}
	for {
		switch activity.Status {
		case "ACTIVITY_STATUS_COMPLETED":
			result := activity.Result.SignSSHUserauthResult
			if result == nil {
				return nil, errors.New("turnkey signature missing")
			}
			signature, err := hex.DecodeString(result.Signature)
			if err != nil || len(signature) != ed25519.SignatureSize {
				return nil, errors.New("turnkey signature malformed")
			}
			return signature, nil
		case "ACTIVITY_STATUS_CREATED", "ACTIVITY_STATUS_PENDING", "ACTIVITY_STATUS_CONSENSUS_NEEDED":
		case "ACTIVITY_STATUS_REJECTED":
			return nil, errTurnkeyDenied
		default:
			return nil, errors.New("turnkey signing activity failed")
		}
		if !turnkeyActivityIDPattern.MatchString(activity.ID) {
			return nil, errors.New("turnkey signing activity needs approval")
		}
		select {
		case <-ctx.Done():
			// Operators need the activity ID; it is not secret.
			return nil, fmt.Errorf("turnkey signing activity %s still needs approval: %w", activity.ID, ctx.Err())
		case <-time.After(interval):
		}
		id := activity.ID
		activity, err = t.post(ctx, "/public/v1/query/get_activity", map[string]string{"organizationId": t.OrganizationID, "activityId": id})
		if err != nil {
			return nil, err
		}
		if activity.ID != id {
			return nil, errors.New("turnkey returned a different activity")
		}
	}
}

// post sends a stamped request. Errors never include response bodies.
func (t *TurnkeySigner) post(ctx context.Context, path string, payload any) (*turnkeyActivity, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("turnkey request encoding failed")
	}
	stamp, err := t.stamp(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("turnkey URL invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Stamp", stamp)
	resp, err := t.Client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("turnkey unavailable: %w", ctx.Err())
		}
		return nil, errors.New("turnkey unavailable")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, errTurnkeyDenied
	default:
		return nil, fmt.Errorf("turnkey request failed: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errors.New("turnkey response unavailable")
	}
	var out struct {
		Activity *turnkeyActivity `json:"activity"`
	}
	if json.Unmarshal(data, &out) != nil || out.Activity == nil {
		return nil, errors.New("invalid turnkey response")
	}
	return out.Activity, nil
}

// stamp signs body with the API key in Turnkey's X-Stamp format.
func (t *TurnkeySigner) stamp(body []byte) (string, error) {
	digest := sha256.Sum256(body)
	signature, err := ecdsa.SignASN1(rand.Reader, t.APIKey, digest[:])
	if err != nil {
		return "", errors.New("turnkey request signing failed")
	}
	stamp, err := json.Marshal(map[string]string{
		"publicKey": compressedP256(&t.APIKey.PublicKey),
		"signature": hex.EncodeToString(signature),
		"scheme":    "SIGNATURE_SCHEME_TK_API_P256",
	})
	if err != nil {
		return "", errors.New("turnkey request signing failed")
	}
	return base64.RawURLEncoding.EncodeToString(stamp), nil
}

// compressedP256 is the SEC 1 compressed point, Turnkey's API public key format.
func compressedP256(key *ecdsa.PublicKey) string {
	point, _ := key.Bytes() // a parsed P-256 key always encodes as a 65-byte uncompressed point
	compressed := append([]byte{0x02 | point[64]&1}, point[1:33]...)
	return hex.EncodeToString(compressed)
}
