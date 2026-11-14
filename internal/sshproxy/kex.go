package sshproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SSH message numbers (RFC 4253 section 12). KEX reply algorithms below all
// send their reply as message 31 with the host key and its signature.
const (
	msgNewKeys  = 21
	msgKexReply = 31
)

// Bounds on what the recorder buffers before the first NEWKEYS. RFC 4253
// section 6.1 requires support for 35000-byte packets; x/crypto accepts 256 KiB.
const (
	maxBannerBytes   = 64 << 10
	maxKexPacketSize = 256 << 10
)

// kexProof is the server half of the first key exchange: the host key and
// its signature over the exchange hash, which is the SSH session ID.
type kexProof struct {
	hostKey   []byte
	signature []byte
}

// kexRecorder passes a connection through unchanged and records the server's
// first key exchange reply. Before the first NEWKEYS the transport is plaintext
// (RFC 4253 section 6), so no keys are needed. The proof is only a claim: the
// verifier checks the signature over the session ID it is bound to.
type kexRecorder struct {
	net.Conn

	mu      sync.Mutex
	buf     []byte
	banner  bool
	done    bool
	failed  bool
	proof   *kexProof
	readErr error
}

func recordKex(conn net.Conn) *kexRecorder {
	return &kexRecorder{Conn: conn}
}

func (r *kexRecorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		r.observe(p[:n])
		r.mu.Unlock()
	}
	return n, err
}

// observe must be called with mu held.
func (r *kexRecorder) observe(data []byte) {
	if r.done {
		return
	}
	r.buf = append(r.buf, data...)
	if !r.banner {
		// RFC 4253 section 4.2: the server may send other lines before its version line.
		for {
			line := bytes.IndexByte(r.buf, '\n')
			if line < 0 {
				if len(r.buf) > maxBannerBytes {
					r.fail()
				}
				return
			}
			isVersion := bytes.HasPrefix(r.buf, []byte("SSH-"))
			r.buf = r.buf[line+1:]
			if isVersion {
				r.banner = true
				break
			}
		}
	}
	for !r.done {
		if len(r.buf) < 5 {
			return
		}
		length := binary.BigEndian.Uint32(r.buf)
		if length < 2 || length > maxKexPacketSize {
			r.fail()
			return
		}
		if uint64(len(r.buf)) < 4+uint64(length) {
			return
		}
		packet := r.buf[4 : 4+length]
		padding := int(packet[0])
		if padding+1 >= len(packet) {
			r.fail()
			return
		}
		payload := packet[1 : len(packet)-padding]
		switch payload[0] {
		case msgKexReply:
			if r.proof == nil {
				proof, err := parseKexReply(payload[1:])
				if err != nil {
					r.fail()
					return
				}
				r.proof = proof
			}
		case msgNewKeys:
			r.done = true
		}
		r.buf = r.buf[4+length:]
	}
	r.buf = nil
}

func (r *kexRecorder) fail() {
	r.done, r.failed, r.proof, r.buf = true, true, nil, nil
}

// result returns the recorded proof once the first key exchange completed.
func (r *kexRecorder) result() (*kexProof, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.done || r.failed || r.proof == nil {
		return nil, errors.New("SSH host proof unavailable")
	}
	return r.proof, nil
}

func parseKexReply(body []byte) (*kexProof, error) {
	hostKey, rest, ok := sshString(body)
	if !ok {
		return nil, errors.New("malformed key exchange reply")
	}
	if _, rest, ok = sshString(rest); !ok {
		return nil, errors.New("malformed key exchange reply")
	}
	signature, rest, ok := sshString(rest)
	if !ok || len(rest) != 0 {
		return nil, errors.New("malformed key exchange reply")
	}
	return &kexProof{hostKey: bytes.Clone(hostKey), signature: bytes.Clone(signature)}, nil
}

func sshString(data []byte) ([]byte, []byte, bool) {
	if len(data) < 4 {
		return nil, nil, false
	}
	length := binary.BigEndian.Uint32(data)
	if uint64(len(data)-4) < uint64(length) {
		return nil, nil, false
	}
	return data[4 : 4+length], data[4+length:], true
}

// sessionBind encodes the contents of a session-bind@openssh.com agent
// extension (OpenSSH PROTOCOL.agent section 4.7), after the extension name,
// for an authentication rather than a forwarding binding.
func sessionBind(proof *kexProof, sessionID []byte) []byte {
	return ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{proof.hostKey, sessionID, proof.signature, false})
}
