package corebridge

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/sys/unix"
)

func init() {
	// Keep Go runtime safely inside iOS NEPacketTunnelProvider's 50 MB RAM limit
	debug.SetGCPercent(20)
	debug.SetMemoryLimit(28 * 1024 * 1024)
}

var (
	mu          sync.Mutex
	activeBox   *box.Box
	tempBoxes   = make(map[string]*box.Box)
	tempCounter int64
	logMu       sync.Mutex
	logLines    []string
)

func appendLog(msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	ts := time.Now().Format("15:04:05")
	logLines = append(logLines, fmt.Sprintf("%s %s", ts, msg))
	if len(logLines) > 120 {
		logLines = logLines[len(logLines)-120:]
	}
}

// FindUtunFileDescriptor scans open fds for iOS NEPacketTunnelProvider's com.apple.net.utun_control socket.
func FindUtunFileDescriptor() int32 {
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	for fd := 0; fd < 1024; fd++ {
		addr, err := unix.Getpeername(fd)
		if err != nil {
			continue
		}
		addrCTL, ok := addr.(*unix.SockaddrCtl)
		if !ok {
			continue
		}
		if ctlInfo.Id == 0 {
			if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
				continue
			}
		}
		if addrCTL.ID == ctlInfo.Id {
			return int32(fd)
		}
	}
	return -1
}

type iosTunPlatform struct {
	tunFd     int32
	myTunAddr []netip.Addr
}

var _ adapter.PlatformInterface = (*iosTunPlatform)(nil)

func (p *iosTunPlatform) Initialize(networkManager adapter.NetworkManager) error { return nil }
func (p *iosTunPlatform) UsePlatformAutoDetectInterfaceControl() bool           { return false }
func (p *iosTunPlatform) AutoDetectInterfaceControl(fd int) error               { return nil }
func (p *iosTunPlatform) UsePlatformInterface() bool                            { return p.tunFd >= 0 }

func (p *iosTunPlatform) OpenInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	if p.tunFd < 0 {
		return nil, fmt.Errorf("invalid iOS utun fd: %d", p.tunFd)
	}
	// SYSPROTO_CONTROL = 2, UTUN_OPT_IFNAME = 2 on Darwin/iOS
	ifName, err := unix.GetsockoptString(int(p.tunFd), 2, 2)
	if err != nil {
		return nil, fmt.Errorf("query utun name: %w", err)
	}
	options.Name = strings.TrimRight(ifName, "\x00")
	if options.InterfaceMonitor != nil {
		options.InterfaceMonitor.RegisterMyInterface(options.Name)
	}
	dupFd, err := unix.Dup(int(p.tunFd))
	if err != nil {
		return nil, fmt.Errorf("dup utun fd: %w", err)
	}
	options.FileDescriptor = dupFd

	addrs := make([]netip.Addr, 0, len(options.Inet4Address)+len(options.Inet6Address))
	for _, pref := range options.Inet4Address {
		addrs = append(addrs, pref.Addr())
	}
	for _, pref := range options.Inet6Address {
		addrs = append(addrs, pref.Addr())
	}
	p.myTunAddr = addrs
	return tun.New(*options)
}

func (p *iosTunPlatform) ProcessPlatformOptions(options option.TunPlatformOptions) error { return nil }
func (p *iosTunPlatform) UsePlatformDefaultInterfaceMonitor() bool                       { return false }
func (p *iosTunPlatform) CreateDefaultInterfaceMonitor(l logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}
func (p *iosTunPlatform) UsePlatformNetworkInterfaces() bool                     { return false }
func (p *iosTunPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, nil }
func (p *iosTunPlatform) UnderNetworkExtension() bool                            { return p.tunFd >= 0 }
func (p *iosTunPlatform) NetworkExtensionIncludeAllNetworks() bool               { return false }
func (p *iosTunPlatform) ClearDNSCache()                                         {}
func (p *iosTunPlatform) RequestPermissionForWIFIState() error                   { return nil }
func (p *iosTunPlatform) ReadWIFIState(ctx context.Context) adapter.WIFIState    { return adapter.WIFIState{} }
func (p *iosTunPlatform) UsePlatformConnectionOwnerFinder() bool                 { return false }
func (p *iosTunPlatform) FindConnectionOwner(req *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, os.ErrInvalid
}
func (p *iosTunPlatform) UsePlatformWIFIMonitor() bool                             { return false }
func (p *iosTunPlatform) UsePlatformNotification() bool                            { return false }
func (p *iosTunPlatform) SendNotification(n *adapter.Notification) error           { return nil }
func (p *iosTunPlatform) CancelNotification(id string, typeID int32) error         { return nil }
func (p *iosTunPlatform) MyInterfaceAddress() []netip.Addr                         { return p.myTunAddr }
func (p *iosTunPlatform) UsePlatformNeighborResolver() bool                        { return false }
func (p *iosTunPlatform) StartNeighborMonitor(l adapter.NeighborUpdateListener) error { return nil }
func (p *iosTunPlatform) CloseNeighborMonitor(l adapter.NeighborUpdateListener) error { return nil }
func (p *iosTunPlatform) UsePlatformShell() bool                                   { return false }
func (p *iosTunPlatform) CheckPlatformShell() error                                { return os.ErrInvalid }
func (p *iosTunPlatform) OpenShellSession(user *adapter.PlatformUser, cmd string, env []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}
func (p *iosTunPlatform) LookupUser(username string) (*adapter.PlatformUser, error) { return nil, os.ErrInvalid }
func (p *iosTunPlatform) LookupSFTPServer() (string, error)                         { return "", os.ErrInvalid }
func (p *iosTunPlatform) ReadSystemSSHHostKey() ([]byte, error)                     { return nil, os.ErrInvalid }
func (p *iosTunPlatform) TailscaleHostname() string                                 { return "" }
func (p *iosTunPlatform) UsePlatformBridge() bool                                   { return false }
func (p *iosTunPlatform) CreateBridge(opts adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, os.ErrInvalid
}

func startInstance(configJSON string, tunFd int32) (*box.Box, error) {
	ctx := include.Context(context.Background())
	if tunFd >= 0 {
		service.MustRegister[adapter.PlatformInterface](ctx, &iosTunPlatform{tunFd: tunFd})
	}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(configJSON))
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return nil, fmt.Errorf("create sing-box: %w", err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, fmt.Errorf("start sing-box: %w", err)
	}
	return instance, nil
}

// StartTunnelCore starts sing-box bound to iOS utun fd (pass -1 for non-TUN mode). Returns "" on success or error string.
func StartTunnelCore(configJSON string, tunFd int32) string {
	mu.Lock()
	defer mu.Unlock()

	if activeBox != nil {
		_ = activeBox.Close()
		activeBox = nil
	}

	instance, err := startInstance(configJSON, tunFd)
	if err != nil {
		appendLog("ERROR: " + err.Error())
		return err.Error()
	}
	activeBox = instance
	appendLog(fmt.Sprintf("sing-box 1.14.4 started (tunFd=%d)", tunFd))
	return ""
}

func StopTunnelCore() {
	mu.Lock()
	defer mu.Unlock()
	if activeBox != nil {
		_ = activeBox.Close()
		activeBox = nil
		appendLog("sing-box stopped")
	}
}

func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return activeBox != nil
}

// StartTempCore starts an isolated non-TUN sing-box instance for node testing. Returns "OK:<id>" or "ERR:<msg>".
func StartTempCore(configJSON string) string {
	instance, err := startInstance(configJSON, -1)
	if err != nil {
		return "ERR:" + err.Error()
	}
	mu.Lock()
	defer mu.Unlock()
	tempCounter++
	id := fmt.Sprintf("tmp_%d", tempCounter)
	tempBoxes[id] = instance
	return "OK:" + id
}

func StopTempCore(handleID string) {
	mu.Lock()
	inst, ok := tempBoxes[handleID]
	if ok {
		delete(tempBoxes, handleID)
	}
	mu.Unlock()
	if ok && inst != nil {
		_ = inst.Close()
	}
}

func GetLogs() string {
	logMu.Lock()
	defer logMu.Unlock()
	return strings.Join(logLines, "\n")
}

func ClearLogs() {
	logMu.Lock()
	defer logMu.Unlock()
	logLines = nil
}
