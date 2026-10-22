package execd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
)

const MaxCatalogBytes = 64 * 1024 * 1024
const CatalogDirectory = "/var/lib/allowops/catalogs"
const KeyDirectory = "/etc/allowops/catalog-keys"
const StateDirectory = "/var/lib/allowops-exec"

func CatalogHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func CatalogPath(base, id string, version int64) string {
	return filepath.Join(base, CatalogHash(id), strconv.FormatInt(version, 10)+".dsse")
}

// OpenDirectory traverses using directory descriptors and O_NOFOLLOW, including
// all ancestors. The final descriptor remains valid if a path is renamed.
func OpenDirectory(path string, create bool, owner int, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("UNSAFE_DIRECTORY")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr == syscall.ENOENT && create {
			if mkdirErr := syscall.Mkdirat(fd, part, 0700); mkdirErr != nil && mkdirErr != syscall.EEXIST {
				_ = syscall.Close(fd)
				return nil, mkdirErr
			}
			next, openErr = syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		}
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, errors.New("UNSAFE_DIRECTORY")
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != owner || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm() != 0700) {
		_ = f.Close()
		return nil, errors.New("UNSAFE_DIRECTORY")
	}
	return f, nil
}

func readFileAt(dir *os.File, name string, limit int64, owner int, private bool) ([]byte, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || (owner >= 0 && (int(stat.Uid) != owner || info.Mode().Perm()&0022 != 0)) || (private && (info.Mode().Perm() != 0600 || stat.Nlink != 1)) {
		return nil, errors.New("UNSAFE_FILE")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("FILE_TOO_LARGE")
	}
	return data, err
}

func ReadPrivateFile(dir *os.File, name string, limit int64, owner int) ([]byte, error) {
	return readFileAt(dir, name, limit, owner, true)
}

// AtomicWrite uses a private random temporary file and renameat. It never opens
// the old destination, so a symlink there cannot redirect a write.
func AtomicWrite(dir *os.File, name string, data []byte) error {
	return AtomicWriteOwned(dir, name, data, -1, -1)
}

func AtomicWriteOwned(dir *os.File, name string, data []byte, uid, gid int) error {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return errors.New("UNSAFE_FILE")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tempName := ".write-" + hex.EncodeToString(random[:])
	// The random basename is created in the held directory, never via its path.
	fd, err := syscall.Openat(int(dir.Fd()), tempName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tempName)
	defer f.Close()
	defer syscall.Unlinkat(int(dir.Fd()), tempName)
	if _, err = f.Write(data); err != nil {
		return err
	}
	if uid >= 0 {
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = syscall.Renameat(int(dir.Fd()), tempName, int(dir.Fd()), name); err != nil {
		return err
	}
	return dir.Sync()
}

func LoadKeys(path string, owner int) (map[string]ed25519.PublicKey, error) {
	dir, err := OpenDirectory(path, false, owner, false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := readFileAt(dir, entry.Name(), 4096, owner, false)
		if err != nil {
			return nil, errors.New("INVALID_TRUST_ANCHOR")
		}
		key, err := catalog.ParsePublicKey(data)
		if err != nil {
			return nil, errors.New("INVALID_TRUST_ANCHOR")
		}
		keys[catalog.KeyID(key)] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("NO_TRUST_ANCHORS")
	}
	return keys, nil
}

type Cache struct {
	MaxBytes   int64
	CatalogDir string
	KeysDir    string
	StateDir   string
	StateOwner int
	KeyOwner   int
}

func (c Cache) Verify(data []byte, id string, version int64, now time.Time) (*catalog.Package, error) {
	limit := c.MaxBytes
	if limit == 0 {
		limit = MaxCatalogBytes
	}
	if int64(len(data)) > limit {
		return nil, errors.New("CATALOG_TOO_LARGE")
	}
	dir, err := OpenDirectory(c.StateDir, true, c.StateOwner, true)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	defer syscall.Flock(int(dir.Fd()), syscall.LOCK_UN)
	name := CatalogHash(id) + ".version"
	state, err := readFileAt(dir, name, 64, c.StateOwner, true)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return nil, errors.New("INVALID_VERSION_STATE")
	}
	var highest int64
	if err == nil {
		highest, err = strconv.ParseInt(strings.TrimSpace(string(state)), 10, 64)
		if err != nil || highest <= 0 {
			return nil, errors.New("INVALID_VERSION_STATE")
		}
	}
	keys, err := LoadKeys(c.KeysDir, c.KeyOwner)
	if err != nil {
		return nil, err
	}
	envelope, err := catalog.ParseEnvelope(data)
	if err != nil {
		return nil, errors.New("INVALID_CATALOG")
	}
	p, err := catalog.Verify(envelope, keys, catalog.VerifyOptions{Now: now, HighestVersion: highest})
	if err != nil {
		return nil, fmt.Errorf("CATALOG_REJECTED: %w", err)
	}
	if p.CatalogID != id || p.Version != version {
		return nil, errors.New("CATALOG_REF_MISMATCH")
	}
	if p.Version > highest {
		if err := AtomicWrite(dir, name, []byte(strconv.FormatInt(p.Version, 10)+"\n")); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (c Cache) Load(id string, version int64) (*catalog.Package, error) {
	// Catalog bytes are untrusted even when the file is owned by allowops.
	parent := filepath.Dir(CatalogPath(c.CatalogDir, id, version))
	dir, err := openUntrustedDirectory(parent)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	limit := c.MaxBytes
	if limit == 0 {
		limit = MaxCatalogBytes
	}
	data, err := readFileAt(dir, strconv.FormatInt(version, 10)+".dsse", limit, -1, false)
	if err != nil {
		return nil, errors.New("CATALOG_UNAVAILABLE")
	}
	return c.Verify(data, id, version, time.Now())
}

func openUntrustedDirectory(path string) (*os.File, error) {
	// Only the signed contents are trusted; the allowops-owned cache must not
	// grant root a symlink path, FIFO, or unlimited input read.
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = syscall.Close(fd)
		if err != nil {
			return nil, errors.New("UNSAFE_DIRECTORY")
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}
