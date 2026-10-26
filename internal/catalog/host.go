package catalog

import (
	"errors"
	"fmt"
	"github.com/liubing0806/allowops/internal/params"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// RequiresExec is derived from signed action fields, never from caller input.
func (a Action) RequiresExec() bool {
	return a.RunAs != "" || a.Builtin == "mysql_query" || a.Builtin == "redis_command" || a.Builtin == "starrocks_query" || a.Builtin == "dremio_query" || a.Builtin == "starrocks_diag"
}

type HostSupport struct {
	RequiresExec bool     `json:"requires_exec"`
	Supported    bool     `json:"supported"`
	Status       string   `json:"status"`
	Reason       string   `json:"reason,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// ResolveExecutable selects fallbacks only on absence. Existing unsafe files,
// permissions failures and interpreters never cause selection of a later path.
func ResolveExecutable(template []any, fallbacks []string, allow bool) (string, error) {
	candidates := append([]string{template[0].(string)}, fallbacks...)
	for _, program := range candidates {
		real, err := filepath.EvalSymlinks(program)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		resolved := append([]any(nil), template...)
		resolved[0] = real
		defs := map[string]params.Definition{}
		for _, word := range words(template) {
			if name, ok := params.Placeholder(word); ok {
				defs[name] = params.Definition{Type: params.String, Description: name}
			}
		}
		if err := validateExec(resolved, defs, allow); err != nil {
			return "", err
		}
		if err := inspectLocalTemplate(resolved, allow); err != nil {
			return "", err
		}
		return program, nil
	}
	return "", fmt.Errorf("exec[0] unavailable: no candidate exists")
}

func inspectLocalTemplate(template []any, allow bool) error {
	variants, err := commandVariants(template)
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	for _, argv := range variants {
		if err := inspectLocalCommand(argv, cwd, "/usr/sbin:/usr/bin:/sbin:/bin", allow, false); err != nil {
			return err
		}
	}
	return nil
}

// Local wrappers inherit the executor's fixed PATH, with signed env changes.
// Targets in another root/mount namespace retain CheckCommand's name checks.
func inspectLocalCommand(argv []string, cwd, searchPath string, allow, wrapped bool) error {
	program, err := localExecutable(argv[0], cwd, searchPath)
	if err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(program)
	if err != nil {
		return err
	}
	if err := inspectExecutable(program, real, allow, wrapped); err != nil {
		return err
	}
	// busybox also provides ordinary commands; CheckCommand checks it by name.
	if base := filepath.Base(real); !allow && base != "busybox" && runsCommands(append([]string{real}, argv[1:]...)) {
		return fmt.Errorf("exec[0] resolves to %s, which runs commands from its arguments; allow_interpreter required", base)
	}
	name := strings.ToLower(filepath.Base(real))
	switch name {
	case "env", "timeout", "nice", "ionice", "stdbuf", "xargs", "nsenter", "chroot":
	default:
		return nil
	}
	nested, err := nestedCommand(name, argv[1:])
	if err != nil {
		return err
	}
	prefix := argv[1 : len(argv)-len(nested)]
	if name == "nsenter" {
		local, changesContext, err := nsenterLocalFilesystem(prefix, cwd)
		if err != nil {
			return err
		}
		if !local {
			return nil
		}
		if changesContext {
			// -w/-W/-e keep the filesystem, so an absolute target is the file
			// inspected here. The new cwd and PATH are not known in advance.
			cwd, searchPath = unknownContext, unknownContext
		}
	}
	if name == "chroot" {
		local, err := chrootLocalRoot(prefix[len(prefix)-1], cwd)
		if err != nil {
			return err
		}
		if !local {
			return nil
		}
		if !slices.Contains(prefix[:len(prefix)-1], "--skip-chdir") {
			cwd = "/"
		}
	}
	if name == "env" {
		cwd, searchPath, err = envExecutionContext(prefix, cwd, searchPath)
		if err != nil {
			return err
		}
	}
	return inspectLocalCommand(nested, cwd, searchPath, allow, true)
}

// nsenterLocalFilesystem reports whether nsenter keeps the local mount
// namespace and root, so its target is a file of this host. Other namespace
// targets keep the existing name-only checks. changesContext reports whether
// -w/-W/-e replace the working directory or environment (hence PATH).
// An explicit root (-r<dir>, --root=<dir>) is local when chrootLocalRoot says
// so; -r and --root without a directory use the target's root and are not.
func nsenterLocalFilesystem(prefix []string, cwd string) (local, changesContext bool, err error) {
	opts := nsenterOptions()
	for len(prefix) > 0 && prefix[0] != "--" {
		arg := prefix[0]
		n, err := consumeOption(prefix, opts, false)
		if err != nil {
			return false, false, nil // wrapperCommand already rejects malformed options.
		}
		root, hasRoot := "", false
		if strings.HasPrefix(arg, "--") {
			key, value, attached := strings.Cut(arg, "=")
			if key == "--root" {
				if !attached {
					return false, false, nil
				}
				root, hasRoot = value, true
			} else if containsOption("--all --mount", key) {
				return false, false, nil
			}
			if containsOption("--wd --wdns --env", key) {
				changesContext = true
			}
		} else {
			for i := 1; i < len(arg); i++ {
				key := "-" + string(arg[i])
				if key == "-r" {
					if arg[i+1:] == "" {
						return false, false, nil
					}
					root, hasRoot = arg[i+1:], true
					break
				}
				if containsOption("-a -m", key) {
					return false, false, nil
				}
				if containsOption("-w -W -e", key) {
					changesContext = true
				}
				if containsOption(opts.values, key) || containsOption(opts.optional, key) {
					break // remaining bytes are an option operand, not flags.
				}
			}
		}
		if hasRoot {
			if root == "" {
				return false, false, nil // nsenter cannot open an empty root.
			}
			same, err := chrootLocalRoot(root, cwd)
			if err != nil {
				return false, false, err
			}
			if !same {
				return false, false, nil
			}
		}
		prefix = prefix[n:]
	}
	return true, changesContext, nil
}

// chrootLocalRoot reports whether root is the executor's own root directory,
// however it is spelled (//, /., /usr/.., symlinks, /proc/self/root). Such a
// chroot keeps the local filesystem, so its target is inspected like any other
// local one. A root that does not exist cannot be entered and keeps the
// name-only checks; every other failure rejects the command.
func chrootLocalRoot(root, cwd string) (bool, error) {
	if strings.ContainsAny(root, "{}") {
		return false, fmt.Errorf("fixed chroot root required")
	}
	if !filepath.IsAbs(root) {
		if cwd == unknownContext {
			return false, fmt.Errorf("relative chroot root %q: working directory set by nsenter is not known", root)
		}
		root = cwd + "/" + root
	}
	real, err := filepath.EvalSymlinks(root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("chroot root %q: %w", root, err)
	}
	info, err := os.Stat(real)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("chroot root %q: %w", root, err)
	}
	local, err := os.Stat("/")
	if err != nil {
		return false, fmt.Errorf("chroot root %q: %w", root, err)
	}
	return os.SameFile(local, info), nil
}

// unknownContext marks a cwd or PATH that nsenter -w/-W/-e replaced.
const unknownContext = "\x00unknown"

func localExecutable(name, cwd, searchPath string) (string, error) {
	if strings.ContainsAny(name, "{}") {
		return "", fmt.Errorf("fixed local executable required")
	}
	if strings.ContainsRune(name, '/') {
		if !filepath.IsAbs(name) {
			if cwd == unknownContext {
				return "", fmt.Errorf("relative executable %q: working directory set by nsenter is not known", name)
			}
			name = cwd + "/" + name
		}
		return name, nil
	}
	if searchPath == unknownContext {
		return "", fmt.Errorf("executable %q needs PATH, which nsenter -e/-w/-W leaves unknown", name)
	}
	for _, dir := range strings.Split(searchPath, ":") {
		if !filepath.IsAbs(dir) {
			if cwd == unknownContext {
				return "", fmt.Errorf("relative PATH entry %q: working directory set by nsenter is not known", dir)
			}
			dir = cwd + "/" + dir
		}
		path := dir + "/" + name
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			return "", err
		}
	}
	return "", fmt.Errorf("local executable %q unavailable", name)
}

func envExecutionContext(prefix []string, cwd, searchPath string) (string, string, error) {
	// execvp uses the platform default when PATH is absent, including env -i/-u.
	const defaultPath = "/bin:/usr/bin"
	var changeDir *string
	opts := optionSet{values: "-u --unset -C --chdir", flags: "-i --ignore-environment -0 --null -v --debug"}
	for len(prefix) > 0 && strings.HasPrefix(prefix[0], "-") {
		arg := prefix[0]
		if arg == "--" {
			prefix = prefix[1:]
			break
		}
		n, err := consumeOption(prefix, opts, false)
		if err != nil {
			return "", "", err
		}
		key, value, attached := strings.Cut(arg, "=")
		if strings.HasPrefix(arg, "--") {
			if key == "--ignore-environment" {
				searchPath = defaultPath
			}
			if key == "--unset" || key == "--chdir" {
				if !attached {
					value = prefix[1]
				}
			}
		} else {
			for i := 1; i < len(arg); i++ {
				key = "-" + string(arg[i])
				if key == "-i" {
					searchPath = defaultPath
				}
				if key == "-u" || key == "-C" {
					value = arg[i+1:]
					if value == "" {
						value = prefix[1]
					}
					break
				}
			}
		}
		if strings.ContainsAny(value, "{}") {
			return "", "", fmt.Errorf("fixed env execution context required")
		}
		if (key == "-u" || key == "--unset") && value == "PATH" {
			searchPath = defaultPath
		}
		if key == "-C" || key == "--chdir" {
			// env applies its final -C once, relative to its original cwd.
			changeDir = &value
		}
		prefix = prefix[n:]
	}
	if changeDir != nil {
		dir := *changeDir
		if !filepath.IsAbs(dir) {
			if cwd == unknownContext {
				return "", "", fmt.Errorf("relative env chdir %q: working directory set by nsenter is not known", dir)
			}
			dir = cwd + "/" + dir
		}
		var err error
		cwd, err = filepath.EvalSymlinks(dir)
		if err != nil {
			return "", "", err
		}
		info, err := os.Stat(cwd)
		if err != nil {
			return "", "", err
		}
		if !info.IsDir() {
			return "", "", fmt.Errorf("env chdir requires a directory")
		}
	}
	for _, assignment := range prefix {
		key, value, _ := strings.Cut(assignment, "=")
		if key == "PATH" {
			if strings.ContainsAny(value, "{}") {
				return "", "", fmt.Errorf("fixed env PATH required")
			}
			searchPath = value
		}
	}
	return cwd, searchPath, nil
}

// inspectExecutable rejects interpreters and scripts. A program started by a
// wrapper (wrapped) goes through execvp, which hands any executable file that
// is neither ELF nor "#!" to /bin/sh (ENOEXEC fallback). Such a target must be
// ELF; anything else is a script. The top-level program is started directly
// by the executor, where ENOEXEC is an error, so only "#!" is rejected there.
func inspectExecutable(program, real string, allow, wrapped bool) error {
	if IsInterpreter(real) && !allow {
		return fmt.Errorf("exec[0] resolves to an interpreter")
	}
	f, err := os.OpenFile(program, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("exec[0] is not an executable regular file")
	}
	var header [4]byte
	n, err := io.ReadFull(f, header[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}
	if n >= 2 && string(header[:2]) == "#!" && !allow {
		return fmt.Errorf("exec[0] is a shebang script; allow_interpreter required")
	}
	if wrapped && !allow && string(header[:n]) != "\x7fELF" {
		return fmt.Errorf("wrapped target is not an ELF executable and would run as a script; allow_interpreter required")
	}
	return nil
}

func CheckHost(a Action) HostSupport {
	warnings, err := ValidateAction(a)
	if err == nil {
		switch {
		case a.Exec != nil:
			_, err = ResolveExecutable(a.Exec, a.ExecFallbacks, a.AllowInterpreter)
		case a.Steps != nil:
			for _, step := range a.Steps {
				if _, err = ResolveExecutable(step.Exec, nil, a.AllowInterpreter); err != nil {
					break
				}
			}
		case a.Script != nil:
			_, err = ResolveExecutable([]any{a.Script.Interpreter}, nil, true)
		}
	}
	if err != nil {
		return HostSupport{RequiresExec: a.RequiresExec(), Status: "unsupported", Reason: err.Error(), Warnings: warnings}
	}
	return HostSupport{RequiresExec: a.RequiresExec(), Supported: true, Status: "supported", Warnings: warnings}
}
