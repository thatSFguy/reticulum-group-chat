//go:build interop

// Package interop runs live cross-implementation tests against an upstream
// Python rns + LXMF install via a stdin/stdout subprocess helper.
//
// Run with:
//
//	go test -tags=interop ./tests/interop/...
//
// Skipped when not requested. Requires `python` on PATH and
// `pip install rns lxmf` (rns >= 1.2.0, LXMF >= 0.9.6).
package interop

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/thatSFguy/reticulum-group-chat/internal/lxmf"
	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// pythonPeer wraps the helper subprocess and serializes JSON ops over its
// stdin/stdout.
type pythonPeer struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
	mu  sync.Mutex
	t   *testing.T
}

func startPythonPeer(t *testing.T) *pythonPeer {
	t.Helper()
	pyExe := "python"
	if runtime.GOOS == "windows" {
		pyExe = "python"
	}
	if _, err := exec.LookPath(pyExe); err != nil {
		t.Skipf("python not on PATH: %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	scriptPath := filepath.Join(filepath.Dir(thisFile), "python_peer.py")

	cmd := exec.Command(pyExe, scriptPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start python helper: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
		if stderr.Len() > 0 {
			t.Logf("python stderr:\n%s", stderr.String())
		}
	})

	return &pythonPeer{
		cmd: cmd,
		in:  stdin,
		out: bufio.NewReader(stdout),
		t:   t,
	}
}

func (p *pythonPeer) call(op string, args map[string]any) map[string]any {
	p.t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()

	if args == nil {
		args = map[string]any{}
	}
	args["op"] = op
	line, err := json.Marshal(args)
	if err != nil {
		p.t.Fatalf("marshal: %v", err)
	}
	if _, err := p.in.Write(append(line, '\n')); err != nil {
		p.t.Fatalf("write to python: %v", err)
	}

	resp, err := p.out.ReadBytes('\n')
	if err != nil {
		p.t.Fatalf("read python response: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(resp, &out); err != nil {
		p.t.Fatalf("decode python response %q: %v", string(resp), err)
	}
	if ok, _ := out["ok"].(bool); !ok {
		p.t.Fatalf("python op %s failed: %v", op, out["error"])
	}
	return out
}

func TestInteropAnnouncePythonToGo(t *testing.T) {
	peer := startPythonPeer(t)
	peer.call("init_rns", nil)

	peer.call("make_identity", map[string]any{"label": "alice"})
	r := peer.call("build_announce", map[string]any{
		"label":        "alice",
		"full_name":    lxmf.FullName(),
		"display_name": "AliceLive",
	})
	wireHex := r["wire_bytes_hex"].(string)
	wantDest := r["dest_hash_hex"].(string)

	wire, err := hex.DecodeString(wireHex)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := rns.ParsePacket(wire)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if hex.EncodeToString(pkt.DestHash) != wantDest {
		t.Errorf("dest_hash mismatch:\n got %x\nwant %s", pkt.DestHash, wantDest)
	}
	a, err := rns.ParseAnnounce(pkt)
	if err != nil {
		t.Fatalf("ParseAnnounce: %v", err)
	}
	if err := a.Verify(); err != nil {
		t.Fatalf("Go Verify rejected Python-built announce: %v", err)
	}
	name, err := rns.DecodeLXMFAppDataDisplayName(a.AppData)
	if err != nil {
		t.Fatal(err)
	}
	if string(name) != "AliceLive" {
		t.Errorf("display_name = %q, want AliceLive", name)
	}
}

func TestInteropAnnounceGoToPython(t *testing.T) {
	peer := startPythonPeer(t)
	peer.call("init_rns", nil)

	id, err := rns.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	appData, _ := rns.EncodeLXMFAppData([]byte("BobLive"), nil)
	pkt, err := rns.BuildAnnounce(id, lxmf.FullName(), appData, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := pkt.Pack()
	if err != nil {
		t.Fatal(err)
	}

	r := peer.call("validate_announce", map[string]any{
		"wire_bytes_hex": hex.EncodeToString(wire),
	})
	if v, _ := r["verified"].(bool); !v {
		t.Fatalf("Python validate_announce rejected Go-built announce: %v", r["error"])
	}
	if r["dest_hash_hex"].(string) != hex.EncodeToString(id.DestinationHashFor(lxmf.FullName())) {
		t.Errorf("dest_hash mismatch")
	}
	if r["pub_hex"].(string) != hex.EncodeToString(id.PublicKey()) {
		t.Errorf("pub_hex mismatch:\n got %s\nwant %s", r["pub_hex"], hex.EncodeToString(id.PublicKey()))
	}
}

func TestInteropLXMFPythonToGo(t *testing.T) {
	peer := startPythonPeer(t)
	peer.call("init_rns", nil)

	// Make alice + bob in Python; pull their priv keys so Go can also load
	// bob (the recipient).
	peer.call("make_identity", map[string]any{"label": "alice"})
	bobInfo := peer.call("make_identity", map[string]any{"label": "bob"})
	bobPriv, _ := hex.DecodeString(bobInfo["priv_hex"].(string))
	bob, err := rns.IdentityFromPrivateKey(bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Have Python build + Token-encrypt an LXMF from alice -> bob.
	r := peer.call("build_lxmf", map[string]any{
		"src_label":     "alice",
		"dst_label":     "bob",
		"dst_full_name": lxmf.FullName(),
		"title":         "live test",
		"content":       "hi from python",
	})
	ciphertext, _ := hex.DecodeString(r["ciphertext_hex"].(string))

	// Go decrypts.
	plain, err := rns.TokenDecrypt(bob, ciphertext)
	if err != nil {
		t.Fatalf("Go TokenDecrypt rejected Python ciphertext: %v", err)
	}
	bobDest := bob.DestinationHashFor(lxmf.FullName())
	m, err := lxmf.ParseOpportunisticBody(plain, bobDest)
	if err != nil {
		t.Fatalf("ParseOpportunisticBody: %v", err)
	}
	if string(m.Content) != "hi from python" {
		t.Errorf("content = %q, want %q", m.Content, "hi from python")
	}
	if string(m.Title) != "live test" {
		t.Errorf("title = %q, want %q", m.Title, "live test")
	}

	// Verify Alice's signature via the public key Python tells us about.
	aliceInfo := peer.call("make_identity", map[string]any{"label": "alice"})
	alicePriv, _ := hex.DecodeString(aliceInfo["priv_hex"].(string))
	alice, _ := rns.IdentityFromPrivateKey(alicePriv)
	if err := m.Verify(alice.PublicKey()[32:]); err != nil {
		t.Errorf("Go Verify rejected Python-signed LXMF: %v", err)
	}
}

func TestInteropLXMFGoToPython(t *testing.T) {
	peer := startPythonPeer(t)
	peer.call("init_rns", nil)

	// Generate alice + bob in Go, ship their priv hex over so Python can
	// load both — Python is the receiver here, so it needs Bob's priv;
	// it also needs Alice's priv so it can compute Alice's pub for sig
	// verify (we'd normally inject Alice via an announce, but for a single
	// LXMF send the priv-hex shortcut is fine).
	alice, _ := rns.NewIdentity()
	bob, _ := rns.NewIdentity()

	peer.call("make_identity", map[string]any{
		"label":    "alice",
		"priv_hex": hex.EncodeToString(alice.PrivateKey()),
	})
	peer.call("make_identity", map[string]any{
		"label":    "bob",
		"priv_hex": hex.EncodeToString(bob.PrivateKey()),
	})

	// Build + Token-encrypt in Go.
	bobDest := bob.DestinationHashFor(lxmf.FullName())
	body, _, err := lxmf.SignAndPackOpportunistic(
		alice,
		alice.DestinationHashFor(lxmf.FullName()),
		bobDest,
		[]byte("live test"),
		[]byte("hi from go"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := rns.TokenEncrypt(body, bob.X25519Public(), bob.Hash())
	if err != nil {
		t.Fatal(err)
	}

	// Have Python decrypt + verify. RNS.Identity.recall uses known_destinations
	// keyed on dest_hash, which gets populated by make_identity calls? It actually
	// does NOT — known_destinations is populated by validate_announce only. So
	// we feed Alice's announce in too so Python knows her pub key for sig verify.
	appData, _ := rns.EncodeLXMFAppData([]byte("AliceLive"), nil)
	aPkt, _ := rns.BuildAnnounce(alice, lxmf.FullName(), appData, nil)
	aWire, _ := aPkt.Pack()
	res := peer.call("validate_announce", map[string]any{"wire_bytes_hex": hex.EncodeToString(aWire)})
	if v, _ := res["verified"].(bool); !v {
		t.Fatalf("Python rejected Alice's announce: %v", res["error"])
	}

	// Now decrypt + parse the LXMF.
	r := peer.call("decrypt_lxmf", map[string]any{
		"ciphertext_hex": hex.EncodeToString(ciphertext),
		"dst_label":      "bob",
		"dst_full_name":  lxmf.FullName(),
	})
	if v, _ := r["verified"].(bool); !v {
		t.Fatalf("Python rejected Go-built LXMF: %+v", r)
	}
	if r["content"].(string) != "hi from go" {
		t.Errorf("content = %q, want %q", r["content"], "hi from go")
	}
	if r["title"].(string) != "live test" {
		t.Errorf("title = %q, want %q", r["title"], "live test")
	}

	// Sanity: source_hash matches Alice's dest hash.
	wantSrc := hex.EncodeToString(alice.DestinationHashFor(lxmf.FullName()))
	if r["source_hash_hex"].(string) != wantSrc {
		t.Errorf("source_hash mismatch: got %s, want %s", r["source_hash_hex"], wantSrc)
	}
}
