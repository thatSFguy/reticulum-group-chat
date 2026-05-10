//go:build interop

// Package interop's harness test runs end-to-end live tests against an
// upstream Python rnsd + LXMF stack on localhost. Spawns:
//
//  1. Python rnsd as a TCPServerInterface on a free local port
//  2. fwdsvc binary connected to that rnsd via TCPClientInterface
//  3. Each Python case script in ./cases/ as a separate subprocess
//
// All traffic stays on loopback — no chicagonomad, no operator interference.
//
// Run with:
//
//	go test -tags=interop -v ./tests/interop/... -run TestHarness
//
// Skipped automatically when prerequisites aren't installed (rnsd /
// python / RNS / LXMF). See tests/interop/README.md for setup.
package interop

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fwdsvcDeliveryRe extracts the delivery destination hash from fwdsvc's
// startup log line, e.g.
//
//	fwdsvc 2026/05/10 07:35:16.483190 delivery destination : e00caf0c...
var fwdsvcDeliveryRe = regexp.MustCompile(`delivery destination\s*:\s*([0-9a-f]{32})`)

// caseTimeout bounds each Python case. Generous because LXMF with a fresh
// identity can take ~10s to announce + handshake even on loopback.
const caseTimeout = 60 * time.Second

func TestHarness(t *testing.T) {
	requireExe(t, "rnsd")
	pyExe := requireExe(t, "python")
	requirePyImport(t, pyExe, "RNS", "LXMF")
	fwdsvcBin := requireFwdsvc(t)

	// One rnsd shared across cases (cheap), but a fresh fwdsvc per case
	// so each case starts with empty roster + history. Without per-case
	// fwdsvc isolation, an early case's /join leaks into a later case's
	// /users assertion.
	port, err := pickFreePort()
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	t.Logf("harness using localhost TCP port %d", port)

	rnsdDir := t.TempDir()
	writeRnsdConfig(t, rnsdDir, port)
	rnsdCancel := spawnRnsd(t, rnsdDir)
	defer rnsdCancel()

	if err := waitForListen("127.0.0.1", port, 15*time.Second); err != nil {
		t.Fatalf("rnsd never started listening on :%d: %v", port, err)
	}

	cases := discoverCases(t)
	if len(cases) == 0 {
		t.Fatal("no Python case scripts found under tests/interop/cases/")
	}
	for _, c := range cases {
		name := strings.TrimSuffix(filepath.Base(c), ".py")
		t.Run(name, func(t *testing.T) {
			fwdsvcDir := t.TempDir()
			maybePreloadState(t, c, fwdsvcDir)
			cfgPath := writeFwdsvcConfig(t, fwdsvcDir, port)
			fwdsvcCancel, deliveryHash := spawnFwdsvc(t, fwdsvcBin, cfgPath, fwdsvcDir)
			defer fwdsvcCancel()
			t.Logf("fwdsvc delivery hash = %s", deliveryHash)
			runCase(t, pyExe, c, port, deliveryHash, fwdsvcDir)
		})
	}
}

// maybePreloadState copies cases/<name>.preload.state.json into the
// fwdsvc state dir before fwdsvc boots, when such a file exists. Lets a
// case start with a populated roster / banlist instead of empty state —
// useful for tests that need 50+ users without the case itself having
// to /join 50 ephemeral identities.
func maybePreloadState(t *testing.T, casePath, fwdsvcDir string) {
	t.Helper()
	base := strings.TrimSuffix(casePath, ".py")
	preload := base + ".preload.state.json"
	src, err := os.ReadFile(preload)
	if err != nil {
		if !os.IsNotExist(err) {
			t.Fatalf("read preload %s: %v", preload, err)
		}
		return
	}
	dst := filepath.Join(fwdsvcDir, "state.json")
	if err := os.WriteFile(dst, src, 0644); err != nil {
		t.Fatalf("write preload to %s: %v", dst, err)
	}
	t.Logf("preloaded %d bytes from %s into fwdsvc state.json",
		len(src), filepath.Base(preload))
}

// requireExe fails the test if exe isn't on PATH. Returns the resolved
// absolute path on success.
func requireExe(t *testing.T, exe string) string {
	t.Helper()
	p, err := exec.LookPath(exe)
	if err != nil {
		t.Skipf("%s not on PATH (install instructions: tests/interop/README.md): %v", exe, err)
	}
	return p
}

// requirePyImport skips the test when one of the listed Python modules
// isn't importable. Catches the common case of `pip install rns lxmf`
// not having been run.
func requirePyImport(t *testing.T, py string, mods ...string) {
	t.Helper()
	stmt := ""
	for _, m := range mods {
		stmt += "import " + m + ";"
	}
	cmd := exec.Command(py, "-c", stmt)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("python module(s) not importable (need: pip install rns lxmf):\n%s%v", out, err)
	}
}

// requireFwdsvc returns a path to a freshly built fwdsvc binary in a
// tempdir. Building from source rather than reusing whatever is in the
// repo root makes the harness deterministic across local + CI.
func requireFwdsvc(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fwdsvc")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/fwdsvc")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build fwdsvc:\n%s%v", out, err)
	}
	return bin
}

// repoRoot walks up from this test file's location until it finds go.mod.
// Lets the harness find ./cmd/fwdsvc and ./tests/interop/cases regardless
// of where `go test` was invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod walking up from test file")
		}
		dir = parent
	}
}

// pickFreePort asks the OS for a free TCP port and returns it. The port
// briefly held by the listener is released before the function returns;
// there's a tiny TOCTOU window before the harness reuses it but in
// practice on a quiet host it's fine.
func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

// waitForListen polls until something accepts connections on host:port,
// or the deadline expires.
func waitForListen(host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("nothing listening on %s after %s", addr, timeout)
}

// writeRnsdConfig drops a Reticulum config into dir/config that brings
// up a single TCPServerInterface on localhost:port. Transport mode is
// enabled so the rnsd will route between connected clients (fwdsvc and
// the Python case scripts).
func writeRnsdConfig(t *testing.T, dir string, port int) {
	t.Helper()
	cfg := fmt.Sprintf(`[reticulum]
enable_transport = yes
share_instance = no
panic_on_interface_error = no

[interfaces]

  [[Default Interface]]
    type = AutoInterface
    enabled = no

  [[harness]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = %d
`, port)
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(cfg), 0644); err != nil {
		t.Fatalf("write rnsd config: %v", err)
	}
}

// spawnRnsd starts the rnsd subprocess against the config dir we wrote.
// Returns a cancel function that stops the daemon and dumps captured
// output if the test failed.
func spawnRnsd(t *testing.T, configDir string) func() {
	t.Helper()
	cmd := exec.Command("rnsd", "--config", configDir, "-v", "-v", "-v")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rnsd: %v", err)
	}

	var out strings.Builder
	var mu sync.Mutex
	tee := func(r io.Reader, label string) {
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 64*1024), 1024*1024)
		for s.Scan() {
			mu.Lock()
			fmt.Fprintf(&out, "[%s] %s\n", label, s.Text())
			mu.Unlock()
		}
	}
	go tee(stdout, "rnsd")
	go tee(stderr, "rnsd!")

	return func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			mu.Lock()
			t.Logf("rnsd output:\n%s", out.String())
			mu.Unlock()
		}
	}
}

// writeFwdsvcConfig builds a minimal fwdsvc config that points at our
// localhost rnsd and stores all state inside dir. Identity is left
// auto-generated on first start so each harness run gets a fresh
// service identity (no contamination from a prior run).
func writeFwdsvcConfig(t *testing.T, dir string, port int) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := fmt.Sprintf(`[service]
display_name      = "Interop Test Forwarder"
identity_path     = %q
state_path        = %q
history_path      = %q
log_path          = %q
prune_after       = "4w"
prune_interval    = "1h"
announce_interval = "10m"
max_inbound_chars = 500
max_members       = 0

[[interfaces]]
type    = "tcp_client"
addr    = "127.0.0.1:%d"
timeout = "10s"

[replay]
count   = 100
max_age = "7d"

admins = []
mods   = []
`,
		filepath.Join(dir, "identity"),
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "history.json"),
		filepath.Join(dir, "fwdsvc.log"),
		port,
	)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatalf("write fwdsvc config: %v", err)
	}
	return cfgPath
}

// spawnFwdsvc starts fwdsvc with the harness config and parses its
// startup output for the delivery destination hash. Returns a cancel
// closure and the hash. Times out after 30s if the daemon never logs
// the expected line.
func spawnFwdsvc(t *testing.T, bin, configPath, dir string) (func(), string) {
	t.Helper()
	cmd := exec.Command(bin, "--config", configPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fwdsvc: %v", err)
	}

	var out strings.Builder
	var mu sync.Mutex
	hashCh := make(chan string, 1)
	scan := func(r io.Reader, label string) {
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 64*1024), 1024*1024)
		for s.Scan() {
			line := s.Text()
			mu.Lock()
			fmt.Fprintf(&out, "[%s] %s\n", label, line)
			mu.Unlock()
			if m := fwdsvcDeliveryRe.FindStringSubmatch(line); m != nil {
				select {
				case hashCh <- m[1]:
				default:
				}
			}
		}
	}
	go scan(stdout, "fwdsvc")
	go scan(stderr, "fwdsvc!")

	cleanup := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			mu.Lock()
			t.Logf("fwdsvc output:\n%s", out.String())
			mu.Unlock()
		}
	}

	select {
	case hash := <-hashCh:
		return cleanup, hash
	case <-time.After(30 * time.Second):
		cleanup()
		mu.Lock()
		t.Fatalf("fwdsvc never logged delivery destination within 30s; output:\n%s", out.String())
		mu.Unlock()
	}
	return cleanup, "" // unreachable
}

// discoverCases finds every *.py file in tests/interop/cases/ excluding
// any leading underscore (reserved for shared-module helpers).
func discoverCases(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "tests", "interop", "cases")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cases dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".py") || strings.HasPrefix(name, "_") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out
}

// runCase invokes a single Python case with --rnsd and --fwdsvc args
// and asserts exit code 0 within caseTimeout. If the case name contains
// "_xfail", a non-zero exit is reported as a known failure (expected
// to fail today, will be flipped to a real assertion when fixed).
func runCase(t *testing.T, py, script string, port int, fwdsvcHash, fwdsvcDir string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, py,
		script,
		"--rnsd", fmt.Sprintf("127.0.0.1:%d", port),
		"--fwdsvc", fwdsvcHash,
	)
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1", "PYTHONIOENCODING=utf-8")

	out, err := cmd.CombinedOutput()
	xfail := strings.Contains(filepath.Base(script), "_xfail")

	if ctx.Err() == context.DeadlineExceeded {
		if xfail {
			t.Logf("case timed out (xfail; %s):\n%s", caseTimeout, out)
			t.Skipf("xfail timeout — case will be enabled once the underlying bug is fixed")
		}
		t.Fatalf("case timed out after %s; output:\n%s", caseTimeout, out)
	}

	if err != nil {
		if xfail {
			t.Logf("case failed (xfail):\n%s%v", out, err)
			t.Skipf("xfail — case will be enabled once the underlying bug is fixed")
		}
		t.Fatalf("case failed: %v\noutput:\n%s", err, out)
	}
	t.Logf("case output:\n%s", out)
}
