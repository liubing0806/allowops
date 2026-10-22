package catalog

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/liubing0806/allowops/internal/params"
)

// CheckCommand is also called after rendering, so enum values and optional lists
// cannot move an unchecked command into a wrapper's executable position.
func CheckCommand(argv []string, allowInterpreter bool) error {
	if len(argv) == 0 {
		return fmt.Errorf("command required")
	}
	command := argv[0]
	if _, dynamic := params.Placeholder(command); dynamic || command == "" || strings.HasPrefix(command, "-") {
		return fmt.Errorf("fixed command required")
	}
	name := strings.ToLower(filepath.Base(command))
	if name == "sudo" {
		return fmt.Errorf("sudo forbidden; use run_as")
	}
	if IsInterpreter(command) && !allowInterpreter {
		return fmt.Errorf("interpreter %s forbidden; allow_interpreter required", command)
	}
	if runsCommands(argv) && !allowInterpreter {
		return fmt.Errorf("%s runs commands from its arguments; allow_interpreter required", command)
	}
	args := argv[1:]
	nested, err := nestedCommand(name, args)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if nested != nil {
		return CheckCommand(nested, allowInterpreter)
	}
	return nil
}

func nestedCommand(name string, args []string) ([]string, error) {
	switch name {
	case "docker", "kubectl":
		return containerCommand(name, args)
	case "env", "timeout", "nice", "ionice", "stdbuf", "xargs", "nsenter", "chroot":
		return wrapperCommand(name, args)
	}
	return nil, nil
}

// executionPrefix includes wrapper operands and the final executable, but not
// that executable's arguments. xargs substitutions may only affect the latter.
func executionPrefix(argv []string) (int, error) {
	if len(argv) == 0 {
		return 0, fmt.Errorf("command required")
	}
	nested, err := nestedCommand(strings.ToLower(filepath.Base(argv[0])), argv[1:])
	if err != nil {
		return 0, err
	}
	if nested == nil {
		if name := strings.ToLower(filepath.Base(argv[0])); name == "docker" || name == "kubectl" {
			return len(argv), nil
		}
		return 1, nil
	}
	prefix, err := executionPrefix(nested)
	return len(argv) - len(nested) + prefix, err
}

type optionSet struct{ values, flags, optional string }

func nsenterOptions() optionSet {
	return optionSet{values: "-t --target -W --wdns -N --net-socket", flags: "-a --all -F --no-fork --preserve-credentials --follow-context --keep-caps --user-parent -e --env -c --join-cgroup", optional: "-S --setuid -G --setgid -m --mount -u --uts -i --ipc -n --net -p --pid -C --cgroup -U --user -T --time -r --root -w --wd"}
}

func containsOption(list, key string) bool {
	for _, v := range strings.Fields(list) {
		if v == key {
			return true
		}
	}
	return false
}

// consumeOption refuses unknown/splitting options instead of guessing argv positions.
func consumeOption(args []string, opts optionSet, rejectTTY bool) (int, error) {
	arg := args[0]
	invalid := fmt.Errorf("unknown or ambiguous option %q", arg)
	if strings.HasPrefix(arg, "--") {
		key, _, attached := strings.Cut(arg, "=")
		if rejectTTY && key == "--tty" {
			return 0, fmt.Errorf("tty forbidden")
		}
		if containsOption(opts.optional, key) {
			return 1, nil
		}
		if containsOption(opts.flags, key) && !attached {
			return 1, nil
		}
		if containsOption(opts.values, key) {
			if attached {
				return 1, nil
			}
			if len(args) > 1 {
				return 2, nil
			}
		}
		return 0, invalid
	}
	for i := 1; i < len(arg); i++ {
		key := "-" + string(arg[i])
		if rejectTTY && key == "-t" {
			return 0, fmt.Errorf("tty forbidden")
		}
		if containsOption(opts.optional, key) {
			return 1, nil
		}
		if containsOption(opts.values, key) {
			if i+1 < len(arg) {
				return 1, nil
			}
			if len(args) > 1 {
				return 2, nil
			}
			return 0, invalid
		}
		if !containsOption(opts.flags, key) {
			return 0, invalid
		}
	}
	if len(arg) < 2 {
		return 0, invalid
	}
	return 1, nil
}

func skipOptions(args []string, opts optionSet, tty bool) ([]string, error) {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		if args[0] == "--" {
			return args[1:], nil
		}
		n, err := consumeOption(args, opts, tty)
		if err != nil {
			return nil, err
		}
		args = args[n:]
	}
	return args, nil
}

func containerCommand(name string, args []string) ([]string, error) {
	globals := optionSet{values: "--config --context --host -H -c", flags: "--debug -D --tls --tlsverify"}
	if name == "kubectl" {
		globals = optionSet{values: "--context --namespace -n --kubeconfig --server -s --cluster --user --token --certificate-authority --request-timeout", flags: "--insecure-skip-tls-verify --warnings-as-errors"}
	}
	args, err := skipOptions(args, globals, false)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("fixed subcommand required")
	}
	if _, dynamic := params.Placeholder(args[0]); dynamic {
		return nil, fmt.Errorf("fixed subcommand required")
	}
	if args[0] != "exec" {
		return nil, nil
	}
	args = args[1:]
	opts := optionSet{values: "--env -e --env-file --user -u --workdir -w --detach-keys", flags: "--interactive -i --privileged --detach -d"}
	if name == "docker" {
		args, err = skipOptions(args, opts, true)
		if err != nil {
			return nil, err
		}
		if len(args) < 2 {
			return nil, fmt.Errorf("container and command required")
		}
		return args[1:], nil
	}
	opts = optionSet{values: "--container -c --filename -f --pod-running-timeout --namespace -n --context --kubeconfig", flags: "--stdin -i --quiet -q"}
	target := false
	for len(args) > 0 {
		if args[0] == "--" {
			if !target || len(args) == 1 {
				return nil, fmt.Errorf("pod and command required")
			}
			return args[1:], nil
		}
		if strings.HasPrefix(args[0], "-") {
			n, e := consumeOption(args, opts, true)
			if e != nil {
				return nil, e
			}
			args = args[n:]
			continue
		}
		if target {
			return nil, fmt.Errorf("kubectl exec requires -- before command")
		}
		target = true
		args = args[1:]
	}
	return nil, fmt.Errorf("kubectl exec requires -- and command")
}

func wrapperCommand(name string, args []string) ([]string, error) {
	options := map[string]optionSet{
		"env":     {values: "-u --unset -C --chdir", flags: "-i --ignore-environment -0 --null -v --debug"},
		"timeout": {values: "-s --signal -k --kill-after", flags: "--preserve-status --foreground -v --verbose"},
		"nice":    {values: "-n --adjustment"},
		"ionice":  {values: "-c --class -n --classdata", flags: "-t --ignore"},
		"stdbuf":  {values: "-i --input -o --output -e --error"},
		"xargs":   {values: "-a --arg-file -d --delimiter -E -I -L -n --max-args -P --max-procs -s --max-chars", optional: "-i --replace -e --eof -l --max-lines", flags: "-0 --null -r --no-run-if-empty -t --verbose -x --exit -p --interactive"},
		"nsenter": nsenterOptions(),
		"chroot":  {values: "--userspec --groups", flags: "--skip-chdir"},
	}

	replacement := ""
	if name == "xargs" {
		var err error
		replacement, err = xargsReplacement(args, options[name])
		if err != nil {
			return nil, err
		}
	}
	var err error
	args, err = skipOptions(args, options[name], false)
	if err != nil {
		return nil, err
	}
	if name == "env" {
		for len(args) > 0 && strings.Contains(args[0], "=") {
			args = args[1:]
		}
	}
	if name == "timeout" || name == "chroot" {
		if len(args) == 0 {
			return nil, fmt.Errorf("operand required")
		}
		args = args[1:]
	}
	if len(args) == 0 {
		if name == "xargs" {
			return []string{"echo"}, nil
		}
		return nil, fmt.Errorf("explicit command required")
	}

	if name == "xargs" && replacement != "" {
		prefix, err := executionPrefix(args)
		if err != nil {
			return nil, err
		}
		for _, word := range args[:prefix] {
			if strings.Contains(word, replacement) {
				return nil, fmt.Errorf("xargs replacement may not alter command or wrapper operands")
			}
		}
	}
	return args, nil
}

func xargsReplacement(args []string, opts optionSet) (string, error) {
	replacement := ""
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "--" {
		arg := args[0]
		n, err := consumeOption(args, opts, false)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(arg, "--") {
			key, value, attached := strings.Cut(arg, "=")
			if key == "--replace" {
				replacement = "{}"
				if attached {
					replacement = value
				}
				if replacement == "" {
					return "", fmt.Errorf("empty xargs replacement forbidden")
				}
			}
		} else {
			for i := 1; i < len(arg); i++ {
				key := "-" + string(arg[i])
				if key == "-I" || key == "-i" {
					replacement = "{}"
					if i+1 < len(arg) {
						replacement = arg[i+1:]
					} else if key == "-I" {
						replacement = args[1]
					}
					if replacement == "" {
						return "", fmt.Errorf("empty xargs replacement forbidden")
					}
					break
				}
				if containsOption(opts.values, key) || containsOption(opts.optional, key) {
					break
				}
			}
		}
		args = args[n:]
	}
	if _, dynamic := params.Placeholder(replacement); dynamic {
		return "", fmt.Errorf("fixed xargs replacement required")
	}
	return replacement, nil
}

func validateExec(template []any, defs map[string]params.Definition, allow bool) error {
	if err := params.ValidateTemplate(template, defs); err != nil {
		return err
	}
	if len(template) == 0 {
		return fmt.Errorf("exec required")
	}
	program, ok := template[0].(string)
	if !ok || !filepath.IsAbs(program) {
		return fmt.Errorf("exec[0] must be a fixed absolute path")
	}
	for _, word := range words(template) {
		if filepath.Base(word) == "sudo" {
			return fmt.Errorf("sudo forbidden in exec; use run_as")
		}
	}
	variants, err := commandVariants(template)
	if err != nil {
		return err
	}
	for _, argv := range variants {
		if err := CheckCommand(argv, allow); err != nil {
			return err
		}
		if err := checkProgramText(argv, defs); err != nil {
			return err
		}
	}
	return nil
}

func commandVariants(template []any) ([][]string, error) {
	variants := [][]string{{}}
	for _, element := range template {
		switch v := element.(type) {
		case string:
			for i := range variants {
				variants[i] = append(variants[i], v)
			}
		case []any:
			if len(variants) > 128 {
				return nil, fmt.Errorf("too many optional command variants")
			}
			original := len(variants)
			for i := 0; i < original; i++ {
				included := append([]string(nil), variants[i]...)
				for _, word := range v {
					included = append(included, word.(string))
				}
				variants = append(variants, included)
			}
		}
	}
	return variants, nil
}
