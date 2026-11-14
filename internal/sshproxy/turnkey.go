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
	"os"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	defaultTurnkeyBaseURL       = "https://api.turnkey.com"
	defaultTurnkeyAPIKeyEnv     = "TURNKEY_API_PRIVATE_KEY"
	turnkeyApprovalPollInterval = time.Second
)

// TurnkeySigner is a RemoteSigner that submits ACTIVITY_TYPE_SIGN_SSH_USERAUTH activities with a
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

func buildTurnkeySigner(node yaml.Node) (*TurnkeySigner, error) {
	var cfg struct {
		BaseURL          string `yaml:"base_url"`
		OrganizationID   string `yaml:"organization_id"`
		APIPrivateKeyEnv string `yaml:"api_private_key_env"`
	}
	if node.Decode(&cfg) != nil {
		return nil, errors.New("invalid turnkey remote signer configuration")
	}
	if cfg.APIPrivateKeyEnv == "" {
		cfg.APIPrivateKeyEnv = defaultTurnkeyAPIKeyEnv
	}
	return NewTurnkeySigner(cfg.BaseURL, cfg.OrganizationID, os.Getenv(cfg.APIPrivateKeyEnv))
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

// HostKeyAlgorithms lists the host key types Turnkey verifies session-binds for.
func (t *TurnkeySigner) HostKeyAlgorithms() []string {
	return []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256}
}

// SignUserauth signs req with the Ed25519 key req.KeyID names, a Turnkey private key ID or address.
func (t *TurnkeySigner) SignUserauth(ctx context.Context, req UserauthRequest) (*ssh.Signature, error) {
	if req.PublicKey.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("turnkey SSH keys must be ssh-ed25519")
	}
	signature, err := t.signUserauth(ctx, req.KeyID, req.Data, req.SessionBind)
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: signature}, nil
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

var errTurnkeyDenied = fmt.Errorf("turnkey: %w", ErrSignatureDenied)

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
