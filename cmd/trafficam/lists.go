package main

// "trafficam lists": view and change your watch and ignore lists without
// learning the file format. The running watcher picks up every change by
// itself within a few seconds; there is nothing to restart.
//
//	trafficam lists                                   show both lists
//	trafficam lists show watch|ignore
//	trafficam lists add watch|ignore PATTERN [PROGRAM] [-note TEXT]
//	trafficam lists add watch|ignore -program NAME    every destination of one program or service
//	trafficam lists remove watch|ignore PATTERN [PROGRAM]   (or -program NAME)
//	trafficam lists edit watch|ignore                 open the file in a text editor
//	trafficam lists path watch|ignore                 print where the file is
//
// PATTERN is a domain (covers its subdomains), an IP address or a network
// such as 198.51.100.0/24. PROGRAM limits the rule to one program (its name,
// full path, or the Windows service / systemd unit it runs). Flags: -data DIR (the watcher's data folder), -file FILE (a
// list file given to the watcher with -watch/-ignore instead).

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Venkatesan7G/trafficam/internal/blocklist"
	"github.com/Venkatesan7G/trafficam/internal/userlists"
)

const listsUsage = `usage:
  trafficam lists [show [watch|ignore]]
  trafficam lists add watch|ignore PATTERN [PROGRAM] [-note TEXT]
  trafficam lists add watch|ignore -program NAME [-note TEXT]   (every destination of a program or service)
  trafficam lists remove watch|ignore PATTERN [PROGRAM]
  trafficam lists remove watch|ignore -program NAME
  trafficam lists edit|path watch|ignore
flags: -data DIR, -file FILE`

func listsCommand(args []string) error {
	opts := map[string]string{"data": defaultListsDir(), "note": "", "file": "", "program": ""}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			pos = append(pos, a)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if _, known := opts[name]; !known {
			return fmt.Errorf("unknown flag %s\n%s", a, listsUsage)
		}
		if !hasVal {
			if i+1 >= len(args) {
				return fmt.Errorf("flag -%s needs a value", name)
			}
			i++
			val = args[i]
		}
		opts[name] = val
	}
	if len(pos) == 0 {
		pos = []string{"show"}
	}
	action := pos[0]
	file := func(k userlists.Kind) userlists.File {
		p := opts["file"]
		if p == "" {
			p = userlists.Path(opts["data"], k)
		}
		return userlists.File{Path: p, Kind: k}
	}
	kind := func() (userlists.Kind, error) {
		if len(pos) < 2 {
			return "", fmt.Errorf("say which list: watch or ignore\n%s", listsUsage)
		}
		return userlists.ParseKind(pos[1])
	}

	switch action {
	case "show":
		kinds := []userlists.Kind{userlists.Watch, userlists.Ignore}
		if len(pos) > 1 {
			k, err := kind()
			if err != nil {
				return err
			}
			kinds = []userlists.Kind{k}
		}
		for _, k := range kinds {
			if err := showList(file(k)); err != nil {
				return err
			}
		}
		return nil

	case "add", "remove":
		k, err := kind()
		if err != nil {
			return err
		}
		if opts["program"] != "" { // -program NAME = every destination of that program
			if len(pos) != 2 {
				return fmt.Errorf("use either PATTERN [PROGRAM] or -program NAME, not both\n%s", listsUsage)
			}
			pos = append(pos, userlists.AnyDestination, opts["program"])
		}
		if len(pos) < 3 || len(pos) > 4 {
			return fmt.Errorf("%s needs PATTERN [PROGRAM]\n%s", action, listsUsage)
		}
		prog := ""
		if len(pos) == 4 {
			prog = pos[3]
		}
		f := file(k)
		if action == "add" {
			changed, err := f.Add(pos[2], prog, opts["note"])
			if err != nil {
				return err
			}
			if !changed {
				fmt.Printf("already on your %s list: %s\n", k, strings.TrimSpace(pos[2]+" "+prog))
				return nil
			}
			fmt.Printf("added to your %s list: %s\n(%s; the watcher picks this up within a few seconds)\n", k, strings.TrimSpace(pos[2]+" "+prog), f.Path)
			return nil
		}
		n, err := f.Remove(pos[2], prog)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%s is not on your %s list (see: trafficam lists show %s)", strings.TrimSpace(pos[2]+" "+prog), k, k)
		}
		fmt.Printf("removed from your %s list: %s\n", k, strings.TrimSpace(pos[2]+" "+prog))
		return nil

	case "edit":
		k, err := kind()
		if err != nil {
			return err
		}
		f := file(k)
		if err := f.Ensure(); err != nil {
			return err
		}
		ed := editorCommand()
		cmd := exec.Command(ed[0], append(ed[1:], f.Path)...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("running %s: %w", ed[0], err)
		}
		// Check the result, so a typo is reported now and not only in the log.
		if _, err := f.Entries(); err != nil {
			return err
		}
		if _, err := blocklist.Load(f.Path); err != nil {
			return fmt.Errorf("the file has a mistake, and the watcher will keep using the previous version until it is fixed: %w", err)
		}
		return showList(f)

	case "path":
		k, err := kind()
		if err != nil {
			return err
		}
		fmt.Println(file(k).Path)
		return nil
	}
	return fmt.Errorf("unknown lists action %q\n%s", action, listsUsage)
}

func showList(f userlists.File) error {
	es, err := f.Entries()
	if err != nil {
		return err
	}
	title := map[userlists.Kind]string{
		userlists.Watch:  "Watch list (always alert)",
		userlists.Ignore: "Ignore list (never alert as new or unusual)",
	}[f.Kind]
	fmt.Printf("%s - %s\n", title, f.Path)
	if len(es) == 0 {
		fmt.Println("  (empty)")
	}
	for _, e := range es {
		line := "  " + e.Pattern
		if e.Pattern == userlists.AnyDestination {
			line = "  every destination of " + e.Program
		} else if e.Program != "" {
			line += "   only for " + e.Program
		}
		if e.Note != "" {
			line += "   # " + e.Note
		}
		fmt.Println(line)
	}
	fmt.Println()
	return nil
}

// editorCommand picks the user's editor: $VISUAL, $EDITOR, then a default.
func editorCommand() []string {
	for _, v := range []string{"VISUAL", "EDITOR"} {
		if e := strings.Fields(os.Getenv(v)); len(e) > 0 {
			return e
		}
	}
	return defaultEditor()
}
