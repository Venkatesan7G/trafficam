//go:build windows

package main

// Running trafficam as a Windows service.
//
// A Windows service starts at boot, before anyone logs in, and runs as
// LocalSystem, which is what ETW capture needs. The commands are:
//
//	trafficam service install [-blocklist F] [-watch F] [-ignore F] [-asn F]
//	trafficam service start
//	trafficam service stop
//	trafficam service uninstall
//
// "install" registers the current trafficam.exe with the Service Control
// Manager (SCM), set to start automatically and to restart itself if it ever
// crashes (5 s, then 30 s, then 1 min). Its data lives in
// %ProgramData%\trafficam, locked so only SYSTEM and Administrators can read
// it. The log goes to %ProgramData%\trafficam\trafficam.log.
//
// Crash safety: trafficam only reads ETW. If the service crashes or is
// stopped, Windows networking carries on exactly as before; the SCM restarts
// us and the new process takes over the old ETW session.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName    = "trafficam"
	serviceDisplay = "trafficam network watcher"
	serviceDesc    = "Passively watches network connections per program and warns about unusual ones. Never blocks traffic."
)

func runningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// serviceDataDir is %ProgramData%\trafficam (usually C:\ProgramData\trafficam).
func serviceDataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "trafficam")
}

func serviceCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trafficam service install|uninstall|start|stop")
	}
	action, rest := args[0], args[1:]
	fs := flag.NewFlagSet("service "+action, flag.ExitOnError)
	data := fs.String("data", serviceDataDir(), "folder for the encrypted database and key")
	var lf listFiles
	fs.StringVar(&lf.blocklist, "blocklist", "", "known-bad snapshot file (opt-in)")
	fs.StringVar(&lf.watch, "watch", "", "your alert-anyway list")
	fs.StringVar(&lf.ignore, "ignore", "", "your ignore list")
	fs.StringVar(&lf.asn, "asn", "", "offline ASN/country table (CSV)")
	fs.Parse(rest)

	switch action {
	case "install":
		return installService(*data, lf)
	case "uninstall":
		return uninstallService()
	case "start":
		return controlService(func(s *mgr.Service) error { return s.Start() }, "started")
	case "stop":
		return controlService(func(s *mgr.Service) error { _, err := s.Control(svc.Stop); return err }, "asked to stop")
	case "run":
		return runService(*data, lf)
	}
	return fmt.Errorf("unknown service action %q", action)
}

func installService(data string, lf listFiles) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	if err := makePrivateDir(data); err != nil {
		return fmt.Errorf("creating %s: %w", data, err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the Service Control Manager (run this from an administrator terminal): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q is already installed; run 'trafficam service uninstall' first", serviceName)
	}
	// The SCM starts: trafficam.exe service run -data ... [-blocklist ...]
	args := []string{"service", "run", "-data", data}
	for flagName, v := range map[string]string{"blocklist": lf.blocklist, "watch": lf.watch, "ignore": lf.ignore, "asn": lf.asn} {
		if v != "" {
			abs, _ := filepath.Abs(v)
			args = append(args, "-"+flagName, abs)
		}
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: serviceDisplay,
		Description: serviceDesc,
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()
	// Restart on crash: 5 s, 30 s, 60 s; the failure count resets after a day.
	err = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60)
	if err == nil {
		// Also restart when we stop ourselves with an error, not only on a crash.
		err = s.SetRecoveryActionsOnNonCrashFailures(true)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not set restart-on-failure:", err)
	}
	fmt.Printf("installed service %q running %s\ndata folder: %s\nstart it with: trafficam service start\n", serviceName, exe, data)
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the Service Control Manager (run this from an administrator terminal): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed", serviceName)
	}
	defer s.Close()
	s.Control(svc.Stop) // fine if it was not running
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Printf("removed service %q (the data folder %s was kept)\n", serviceName, serviceDataDir())
	return nil
}

func controlService(do func(*mgr.Service) error, done string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the Service Control Manager (run this from an administrator terminal): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed", serviceName)
	}
	defer s.Close()
	if err := do(s); err != nil {
		return err
	}
	fmt.Printf("service %q %s\n", serviceName, done)
	return nil
}

// makePrivateDir creates dir and sets its permissions so only SYSTEM and
// the Administrators group can open it (no inherited "Users can read").
// The database is encrypted, but the key file sits next to it.
func makePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// SDDL: protected DACL (P), full access (FA) for SYSTEM (SY) and
	// Administrators (BA), inherited by files (OI) and subfolders (CI).
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// runService is what the SCM runs. It hands control to svc.Run, which calls
// Execute below and reports our state to Windows.
func runService(data string, lf listFiles) error {
	if err := makePrivateDir(data); err != nil {
		return err
	}
	// A service has no console: send the log to a file in the data folder.
	if f, err := os.OpenFile(filepath.Join(data, "trafficam.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		os.Stderr, os.Stdout = f, f
	}
	return svc.Run(serviceName, &winService{data: data, lf: lf})
}

type winService struct {
	data string
	lf   listFiles
}

// Execute is called by Windows. It starts the pipeline, then waits for
// stop/shutdown requests from the SCM.
func (w *winService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runLive(ctx, w.data, w.lf) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-done:
			// The pipeline stopped on its own: that is a failure. Returning a
			// non-zero exit code makes the SCM apply the restart actions.
			fmt.Fprintln(os.Stderr, "trafficam stopped unexpectedly:", err)
			cancel()
			return false, 1
		case r := <-req:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}
