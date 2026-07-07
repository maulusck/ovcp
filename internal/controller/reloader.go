package controller

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
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

// MgmtSignalReloader (compose, k8s): signals via mgmt socket.
// Restart sends SIGTERM; the platform supervisor restarts the container.
type MgmtSignalReloader struct{ C *Client }

func (r *MgmtSignalReloader) Reload() error  { return r.C.Signal("SIGUSR1") }
func (r *MgmtSignalReloader) Restart() error { return r.C.Signal("SIGTERM") }
func (r *MgmtSignalReloader) Name() string   { return "mgmt-signal" }

// SystemdReloader (host installs).
type SystemdReloader struct{ Unit string }

func (r *SystemdReloader) Reload() error  { return r.ctl("reload") }
func (r *SystemdReloader) Restart() error { return r.ctl("restart") }
func (r *SystemdReloader) Name() string   { return "systemd" }
func (r *SystemdReloader) ctl(verb string) error {
	out, err := exec.Command("systemctl", verb, r.Unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("controller: systemctl %s: %v: %s", verb, err, out)
	}
	return nil
}

// ChildSignalReloader (standalone): we own the openvpn child.
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
	PlatformStandalone Platform = "standalone"
	PlatformSystemd    Platform = "systemd"
	PlatformCompose    Platform = "compose"
	PlatformK8s        Platform = "k8s"
)

// DetectPlatform picks the supervision mode at startup. Override: OVCP_PLATFORM.
func DetectPlatform() Platform {
	switch os.Getenv("OVCP_PLATFORM") {
	case "standalone":
		return PlatformStandalone
	case "systemd":
		return PlatformSystemd
	case "compose":
		return PlatformCompose
	case "k8s":
		return PlatformK8s
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return PlatformK8s
	}
	if inContainer() {
		return PlatformCompose
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil && os.Getppid() == 1 {
		return PlatformSystemd
	}
	return PlatformStandalone
}

func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil { // podman
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") ||
			strings.Contains(s, "kubepods") || strings.Contains(s, "libpod") {
			return true
		}
	}
	return false
}

// NewReloader returns the impl for a platform. childPID/respawn are only
// consulted on standalone.
func NewReloader(p Platform, mgmt *Client, systemdUnit string, childPID func() int, respawn func() error) Reloader {
	switch p {
	case PlatformSystemd:
		return &SystemdReloader{Unit: systemdUnit}
	case PlatformCompose, PlatformK8s:
		return &MgmtSignalReloader{C: mgmt}
	default:
		return &ChildSignalReloader{PID: childPID, Respawn: respawn}
	}
}
