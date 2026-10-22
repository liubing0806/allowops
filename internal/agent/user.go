package agent

import (
	"errors"
	"os"
	"os/user"
	"strconv"
)

func allowopsAccount() (int, int, error) {
	account, err := user.Lookup("allowops")
	if err != nil {
		return 0, 0, errors.New("ALLOWOPS_USER_MISSING")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 {
		return 0, 0, errors.New("INVALID_ALLOWOPS_USER")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid <= 0 {
		return 0, 0, errors.New("INVALID_ALLOWOPS_USER")
	}
	return uid, gid, nil
}

// Command callers use the installed account; library tests may run as the
// current unprivileged user with a private temporary data directory.
func CheckCommandUser(join bool) error {
	uid, gid, err := allowopsAccount()
	if err != nil {
		return err
	}
	if join && os.Geteuid() == 0 {
		return nil
	}
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid {
		return errors.New("ALLOWOPS_USER_REQUIRED")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	for _, group := range groups {
		if group != gid {
			return errors.New("EXTRA_GROUPS_FORBIDDEN")
		}
	}
	return nil
}

func identityOwner() (int, int, error) {
	if os.Geteuid() == 0 {
		return allowopsAccount()
	}
	return os.Getuid(), os.Getgid(), nil
}
