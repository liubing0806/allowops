package logsearch

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/liubing0806/allowops/internal/builtin"
)

func TestOutsideRootsReason(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "secret.log")
	writeLog(t, secret, "secret\n")
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	for name, glob := range map[string]string{"lexical": secret, "symlink": link} {
		t.Run(name, func(t *testing.T) {
			_, err := Run(context.Background(), Config{AllowedRoots: []string{dir}}, Params{PathGlob: glob, Pattern: "secret"})
			if got := builtin.ReasonOf(err); got != builtin.ReasonPathOutsideRoots {
				t.Fatalf("reason=%q err=%v", got, err)
			}
		})
	}
}
