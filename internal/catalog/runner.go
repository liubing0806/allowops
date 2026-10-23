package catalog

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/liubing0806/allowops/internal/params"
)

// commandRunners run a command or program text taken from their arguments:
// through a shell, on a remote host, under a tracer, or by a client's shell escape.
var commandRunners = []string{
	"watch", "script", "busybox", "expect", "tclsh", "wish", "fish", "parallel", "time",
	"ssh", "scp", "rsh", "sshpass", "su", "runuser", "pkexec", "doas", "sg",
	"setsid", "setpriv", "flock", "nohup", "chrt", "taskset", "numactl", "unshare", "prlimit", "runcon",
	"capsh", "cgexec", "chpst", "systemd-run", "machinectl", "start-stop-daemon",
	"strace", "ltrace", "gdb", "git", "psql", "mysql", "mariadb", "sqlite3",
}

// runsCommands reports whether argv starts a program that runs another command
// or program text taken from its arguments. Such a program is an interpreter.
func runsCommands(argv []string) bool {
	name := strings.ToLower(filepath.Base(argv[0]))
	args := argv[1:]
	if slices.Contains(commandRunners, name) {
		return true
	}
	switch name {
	case "find":
		return slices.ContainsFunc(args, func(w string) bool { return containsOption("-exec -execdir -ok -okdir", w) })
	case "tar":
		// Old-style options: the first word bundles letters without a dash.
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") && strings.ContainsAny(args[0], "IF") {
			return true
		}
		return namesOption(args, "--to-command --use-compress-program --info-script --new-volume-script --checkpoint-action --rsh-command --rmt-command", "IF", "bCfgHKLNTVX")
	case "rsync":
		return namesOption(args, "--rsh --rsync-path --remote-option", "eM", "BfT")
	case "ip":
		// ip reads "--x" as "-x" and accepts a prefix of an option or command name.
		for _, w := range args {
			if strings.HasPrefix(w, "--") {
				w = w[1:]
			}
			if (len(w) > 1 && strings.HasPrefix("-batch", w)) || (w != "" && strings.HasPrefix("exec", w)) {
				return true
			}
		}
	}
	return false
}

// namesOption reports whether args name one of the long options, including an
// unambiguous prefix GNU getopt would accept, or one of the short letters in a
// bundle before a letter whose value takes the rest of the word.
func namesOption(args []string, long, short, values string) bool {
	for _, w := range args {
		if w == "--" {
			return false
		}
		if strings.HasPrefix(w, "--") {
			key, _, _ := strings.Cut(w, "=")
			for _, option := range strings.Fields(long) {
				if len(key) > 3 && strings.HasPrefix(option, key) {
					return true
				}
			}
			continue
		}
		if !strings.HasPrefix(w, "-") {
			continue
		}
		for _, c := range w[1:] {
			if strings.ContainsRune(short, c) {
				return true
			}
			if strings.ContainsRune(values, c) {
				break
			}
		}
	}
	return false
}

// finalCommand is the command left after unwrapping wrappers.
func finalCommand(argv []string) ([]string, error) {
	for {
		nested, err := nestedCommand(strings.ToLower(filepath.Base(argv[0])), argv[1:])
		if err != nil || nested == nil {
			return argv, err
		}
		argv = nested
	}
}

// checkProgramText keeps an interpreter's options and program text signed under
// allow_interpreter: placeholders may only supply the arguments after them.
func checkProgramText(argv []string, defs map[string]params.Definition) error {
	argv, err := finalCommand(argv)
	if err != nil {
		return err
	}
	name := strings.ToLower(filepath.Base(argv[0]))
	if !slices.ContainsFunc(argv[1:], isPlaceholder) {
		return nil
	}
	if runsCommands(argv) {
		return fmt.Errorf("%s runs commands from its arguments; placeholders forbidden", name)
	}
	if !IsInterpreter(argv[0]) {
		return nil
	}
	syntax, ok := interpreterSyntax(name)
	if !ok {
		return fmt.Errorf("interpreter %s: placeholders forbidden", name)
	}
	args := argv[1:]
	start, err := syntax.arguments(args)
	if err != nil {
		return fmt.Errorf("interpreter %s: %w", name, err)
	}
	for i := start; i < len(args); i++ {
		p, ok := params.Placeholder(args[i])
		if !ok {
			continue
		}
		// Some interpreters still parse options here; a fixed option may take the value.
		if i > start {
			if previous := args[i-1]; strings.HasPrefix(previous, "-") && previous != "--" && previous != "-" {
				return fmt.Errorf("interpreter %s: placeholder {%s} follows option %s", name, p, previous)
			}
		}
		if mayStartWithDash(defs[p]) {
			return fmt.Errorf("interpreter %s: placeholder {%s} may render an option", name, p)
		}
	}
	return nil
}

func isPlaceholder(word string) bool {
	_, ok := params.Placeholder(word)
	return ok
}

func mayStartWithDash(d params.Definition) bool {
	switch d.Type {
	case params.String, params.Path, params.URL, params.Bool, params.Duration:
		return false
	case params.Int:
		return d.Min == nil || *d.Min < 0
	case params.Enum:
		return slices.ContainsFunc(d.Values, func(v string) bool { return strings.HasPrefix(v, "-") })
	}
	return true
}

// programSyntax lists an interpreter's options. Single letters may be bundled:
// flags take no value, attached letters take the rest of the word, and values
// take the rest of the word or the next word. code marks values that are the
// program text, after which operands are arguments. Unknown options are refused,
// since they may take the next word as their value.
type programSyntax struct {
	flags, attached, values, code   string
	longFlags, longValues, longCode string
	plus                            bool
}

func interpreterSyntax(name string) (programSyntax, bool) {
	switch {
	case strings.HasPrefix(name, "python"):
		return programSyntax{flags: "bBdEhiIOPqsSuvVx?", values: "cmWX", code: "cm", longFlags: "--help --version --help-env --help-xoptions --help-all", longValues: "--check-hash-based-pycs"}, true
	case slices.Contains([]string{"sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "rbash", "csh", "tcsh"}, name):
		return programSyntax{flags: "abcefhiklmnprstuvxBCEHPTVXD", values: "oO", plus: true, longFlags: "--norc --noprofile --login --posix --restricted --noediting --verbose --version --help --debugger --dump-strings --dump-po-strings --pretty-print", longValues: "--rcfile --init-file"}, true
	case name == "perl":
		return programSyntax{flags: "acnpsStTuUwWX", attached: "0lFCdDiIMmxV", values: "eE", code: "eE"}, true
	case name == "ruby":
		return programSyntax{flags: "acdlnpsSvwyU", attached: "0FKTWx", values: "erICE", code: "e", longFlags: "--copyright --version --verbose --yydebug --help --jit", longValues: "--enable --disable --encoding --external-encoding --internal-encoding --dump"}, true
	case name == "node":
		return programSyntax{flags: "ichv", values: "eprC", code: "ep", longFlags: "--check --interactive --version --help --no-warnings --no-deprecation --trace-warnings --trace-deprecation --throw-deprecation --pending-deprecation --enable-source-maps --preserve-symlinks --expose-gc --abort-on-uncaught-exception --trace-uncaught --no-addons --frozen-intrinsics --zero-fill-buffers", longValues: "--require --import --loader --experimental-loader --input-type --title --conditions --env-file", longCode: "--eval --print"}, true
	case name == "php":
		return programSyntax{flags: "aCHhilmnqsvwe", values: "BcdEfFRrtz", code: "BEfFRr"}, true
	case name == "lua":
		return programSyntax{flags: "ivEW", values: "el"}, true
	case name == "awk" || name == "gawk" || name == "mawk":
		return programSyntax{flags: "bcCgknNOPrsStVhMy", attached: "dDLop", values: "FvfeEilW", code: "feE", longFlags: "--posix --traditional --lint --sandbox --characters-as-bytes --copyright --version --help --optimize --no-optimize --re-interval --bignum --use-lc-numeric --non-decimal-data --csv", longValues: "--assign --field-separator --include --load", longCode: "--file --source --exec"}, true
	case name == "sed":
		return programSyntax{flags: "nErsuz", attached: "i", values: "efl", code: "ef", longFlags: "--quiet --silent --regexp-extended --separate --unbuffered --null-data --zero-terminated --posix --sandbox --debug --follow-symlinks --in-place --binary", longValues: "--line-length", longCode: "--expression --file"}, true
	}
	return programSyntax{}, false
}

// arguments returns the index of the first word after the options and program
// text, refusing a placeholder among them.
func (s programSyntax) arguments(args []string) (int, error) {
	code := false
	for i := 0; i < len(args); i++ {
		word := args[i]
		if isPlaceholder(word) {
			if code {
				return i, nil
			}
			return 0, fmt.Errorf("placeholder %s supplies the program text", word)
		}
		value := func() error {
			if i+1 == len(args) {
				return fmt.Errorf("option %s requires a value", word)
			}
			i++
			if isPlaceholder(args[i]) {
				return fmt.Errorf("placeholder %s supplies the value of option %s", args[i], word)
			}
			return nil
		}
		switch {
		case word == "--":
			if code || i+1 == len(args) {
				return i + 1, nil
			}
			if isPlaceholder(args[i+1]) {
				return 0, fmt.Errorf("placeholder %s supplies the program text", args[i+1])
			}
			return i + 2, nil
		case word == "-":
			return i + 1, nil
		case strings.HasPrefix(word, "--"):
			key, _, attached := strings.Cut(word, "=")
			switch {
			case containsOption(s.longCode, key):
				code = true
				if !attached {
					if err := value(); err != nil {
						return 0, err
					}
				}
			case containsOption(s.longValues, key) && !attached:
				if err := value(); err != nil {
					return 0, err
				}
			case attached || containsOption(s.longFlags, key):
			default:
				return 0, fmt.Errorf("unknown option %s before a placeholder", word)
			}
		case strings.HasPrefix(word, "-") || s.plus && strings.HasPrefix(word, "+"):
			letters := word[1:]
		bundle:
			for j, c := range letters {
				switch {
				case strings.ContainsRune(s.flags, c):
				case strings.ContainsRune(s.attached, c):
					// Without an attached value, the next word may be read as one.
					if j+1 == len(letters) && i+1 < len(args) && isPlaceholder(args[i+1]) {
						return 0, fmt.Errorf("placeholder %s may supply the value of option %s", args[i+1], word)
					}
					break bundle
				case strings.ContainsRune(s.values, c):
					code = code || strings.ContainsRune(s.code, c)
					if j+1 == len(letters) {
						if err := value(); err != nil {
							return 0, err
						}
					}
					break bundle
				default:
					return 0, fmt.Errorf("unknown option %s before a placeholder", word)
				}
			}
		default:
			if code {
				return i, nil
			}
			return i + 1, nil
		}
	}
	return len(args), nil
}
