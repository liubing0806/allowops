// Static process fixture used only inside the root-test container.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "spawn" {
		child := exec.Command("/usr/bin/sleep", "120")
		if child.Start() != nil {
			os.Exit(1)
		}
		data, _ := json.Marshal([]int{os.Getpid(), child.Process.Pid})
		if os.WriteFile(os.Args[2], data, 0600) != nil {
			os.Exit(2)
		}
		_ = child.Wait()
		return
	}
	groups, err := os.Getgroups()
	if err != nil {
		os.Exit(1)
	}
	environment := map[string]string{}
	for _, name := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "LANG", "PAGER", "SYSTEMD_PAGER", "HOME", "TMPDIR", "ALLOWOPS_CATALOG_DIR"} {
		environment[name] = os.Getenv(name)
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		UID         int               `json:"uid"`
		GID         int               `json:"gid"`
		Groups      []int             `json:"groups"`
		Environment map[string]string `json:"environment"`
	}{os.Getuid(), os.Getgid(), groups, environment})
}
