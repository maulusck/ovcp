package controller

import (
	"fmt"
	"os"
	"syscall"
)

// Reloader applies config changes to the running openvpn.
//
// Reload = soft (SIGUSR1): honors persist-key/persist-tun, safe after
// openvpn drops privileges; picks up CRL and connection-level changes.
// Restart = hard: full process restart with fresh (root) privileges;
// required for port/proto/subnet/key changes.
type Reloader interface {
	Reload() error
	Restart() error
	Name() string
}

// MgmtSignalReloader signals openvpn over the mgmt socket (unprivileged).
// SIGUSR1 = soft reload (CRL/connections). Restart sends SIGTERM: openvpn
// exits and its supervisor (systemd Restart=always) starts it fresh as
// root, so it can re-read root-owned keys after its own privilege drop.
// Also used standalone after ovcp drops privileges and can no longer
// signal the root child directly.
type MgmtSignalReloader struct{ C *Client }

func (r *MgmtSignalReloader) Reload() error  { return r.C.Signal("SIGUSR1") }
func (r *MgmtSignalReloader) Restart() error { return r.C.Signal("SIGTERM") }
func (r *MgmtSignalReloader) Name() string   { return "mgmt-signal" }

// MgmtHUPReloader: standalone after ovcp dropped privileges, where no
// supervisor exists to respawn openvpn. Restart sends SIGHUP: openvpn
// restarts in-process (re-reads config, re-binds sockets) while keeping
// key material in memory (persist-key), so it never needs root again.
// Caveat: a rotated server key requires restarting ovcp itself.
type MgmtHUPReloader struct{ C *Client }

func (r *MgmtHUPReloader) Reload() error  { return r.C.Signal("SIGUSR1") }
func (r *MgmtHUPReloader) Restart() error { return r.C.Signal("SIGHUP") }
func (r *MgmtHUPReloader) Name() string   { return "mgmt-hup" }

// ChildSignalReloader (standalone, incl. containers): we own the openvpn child.
type ChildSignalReloader struct {
	PID     func() int
	Respawn func() error // kill + start fresh child (root privileges again)
}

func (r *ChildSignalReloader) Reload() error {
	pid := r.PID()
	if pid <= 0 {
		return fmt.Errorf("controller: no child openvpn process")
	}
	return syscall.Kill(pid, syscall.SIGUSR1)
}
func (r *ChildSignalReloader) Restart() error {
	if r.Respawn == nil {
		return fmt.Errorf("controller: restart unsupported here")
	}
	return r.Respawn()
}
func (r *ChildSignalReloader) Name() string { return "child-signal" }

type Platform string

const (
	PlatformStandalone Platform = "standalone" // ovcp supervises openvpn (host or container)
	PlatformSystemd    Platform = "systemd"    // ovcp + openvpn as separate units
)

// DetectPlatform picks the supervision mode at startup. Override: OVCP_PLATFORM.
func DetectPlatform() Platform {
	switch os.Getenv("OVCP_PLATFORM") {
	case "standalone":
		return PlatformStandalone
	case "systemd":
		return PlatformSystemd
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil && os.Getppid() == 1 {
		return PlatformSystemd
	}
	return PlatformStandalone
}

// NewReloader returns the impl for a platform. childPID/respawn are only
// consulted on standalone.
func NewReloader(p Platform, mgmt *Client, childPID func() int, respawn func() error) Reloader {
	if p == PlatformSystemd {
		return &MgmtSignalReloader{C: mgmt}
	}
	return &ChildSignalReloader{PID: childPID, Respawn: respawn}
}
