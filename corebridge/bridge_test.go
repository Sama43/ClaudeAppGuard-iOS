package corebridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	boxlog "github.com/sagernet/sing-box/log"
)

// Exercise the actual iOS-generated routing config and cache across two starts.
// Replace only the system TUN and mixed listeners so this test needs no VPN entitlement.
func TestGuardStartsSealedWithExistingCache(t *testing.T) {
	directory := os.Getenv("GUARD_TEST_CONFIGS")
	for _, mode := range []string{"false", "true"} {
		raw, err := os.ReadFile(filepath.Join(directory, "tunnel-"+mode+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var config map[string]any
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		delete(config, "inbounds")
		raw, err = json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		selectedTag := "proxy-" + mode
		func() {
			if err := StartTunnelCore(string(raw), -1); err != "" {
				t.Fatal(err)
			}
			defer StopTunnelCore()
			group, _ := activeBox.Outbound().Outbound("guard")
			selected := func() string { return group.(adapter.OutboundGroup).Selected("tcp").Tag() }
			if selected() != "sealed" || !SelectGuardOutbound(selectedTag) || selected() != selectedTag {
				t.Fatal("unexpected selector state at startup or activation")
			}
			if !SelectGuardOutbound("sealed") || selected() != "sealed" {
				t.Fatal("guard failed to close")
			}
			if !SelectGuardOutbound(selectedTag) {
				t.Fatal("could not persist a previously open selection")
			}
		}()
		if _, err := os.Stat(filepath.Join(directory, "cache.db")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTempCoreUsesTempCachePathInsteadOfCwd(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	roDir := t.TempDir()
	if err := os.Chmod(roDir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(roDir, 0o755) }()
	if err := os.Chdir(roDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()

	cfg := `{"log":{"level":"info","timestamp":false},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080}]}`
	resp := StartTempCore(cfg)
	if !strings.HasPrefix(resp, "OK:") {
		t.Fatalf("StartTempCore failed in read-only cwd: %s", resp)
	}
	handle := strings.TrimPrefix(resp, "OK:")
	_ = GetTempCoreLogs(handle)
	StopTempCore(handle)
}

func TestLogFilteringAndANSIStripping(t *testing.T) {
	lw := &ringLogWriter{}
	lw.WriteMessage(boxlog.LevelTrace, "\x1b[37mTRACE\x1b[0m[0000] outbound/vless[proxy]: XtlsPadding 1523 210 0")
	lw.WriteMessage(boxlog.LevelDebug, "\x1b[37mDEBUG\x1b[0m[0000] connection: download finished")
	lw.WriteMessage(boxlog.LevelError, "\x1b[31mERROR\x1b[0m[0000] dial tcp: i/o timeout")
	got := lw.String()
	if strings.Contains(got, "XtlsPadding") || strings.Contains(got, "DEBUG") {
		t.Fatalf("expected trace/debug logs to be filtered, got: %q", got)
	}
	if got != "ERROR[0000] dial tcp: i/o timeout" {
		t.Fatalf("unexpected stripped log: %q", got)
	}
}
