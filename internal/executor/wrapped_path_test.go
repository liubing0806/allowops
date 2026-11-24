package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWrappedPATHUsesExecutableForCurrentIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can execute a regular file with the other execute bit set")
	}
	first, second := t.TempDir(), t.TempDir()
	const name = "checked-command"
	elf, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(first, name)
	if err := os.WriteFile(denied, elf, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0401); err != nil { // The owner has no execute permission.
		t.Fatal(err)
	}
	selected := filepath.Join(second, name)
	if err := os.WriteFile(selected, elf, 0700); err != nil {
		t.Fatal(err)
	}
	argv, err := renderCommand([]any{"/usr/bin/env", "PATH=" + first + ":" + second, name}, nil, false, nil, nil)
	if err != nil || len(argv) != 3 || argv[2] != selected {
		t.Fatalf("rendered argv=%q err=%v; want checked absolute target %q", argv, err, selected)
	}
}

func TestXargsImplicitTargetIsPinned(t *testing.T) {
	argv, err := renderCommand([]any{"/usr/bin/xargs", "-r"}, nil, false, nil, nil)
	if err != nil || len(argv) != 3 || argv[1] != "-r" || !filepath.IsAbs(argv[2]) || filepath.Base(argv[2]) != "echo" {
		t.Fatalf("rendered argv=%q err=%v; want xargs -r with an absolute echo target", argv, err)
	}
}
