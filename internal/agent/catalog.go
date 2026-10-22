package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"google.golang.org/protobuf/proto"
)

type catalogs struct {
	mu      sync.RWMutex
	install sync.Mutex
	limits  Limits
	loaded  map[string]*catalog.Package
	cache   execd.Cache
}

func (c *catalogs) refs() []*v1.CatalogRef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	refs := make([]*v1.CatalogRef, 0, len(c.loaded))
	for _, p := range c.loaded {
		refs = append(refs, &v1.CatalogRef{CatalogId: p.CatalogID, Version: uint64(p.Version)})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].CatalogId < refs[j].CatalogId })
	return refs
}

func (c *catalogs) put(p *catalog.Package) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loaded[p.CatalogID] = p
}

func (c *catalogs) restore() {
	dir, err := execd.OpenDirectory(c.cache.StateDir, true, os.Getuid(), true)
	if err != nil {
		return
	}
	defer dir.Close()
	data, err := execd.ReadPrivateFile(dir, "loaded.json", MaxMessageBytes, os.Getuid())
	if err != nil {
		return
	}
	var refs []*v1.CatalogRef
	if execd.DecodeJSON(data, &refs) != nil {
		return
	}
	for _, ref := range refs {
		if ref == nil || ref.Version == 0 || ref.Version > 1<<63-1 {
			continue
		}
		p, err := c.cache.Load(ref.CatalogId, int64(ref.Version))
		if err == nil {
			c.put(p)
		}
	}
}

func (c *catalogs) save(p *catalog.Package) error {
	refs := c.refs()
	updated := false
	for _, ref := range refs {
		if ref.CatalogId == p.CatalogID {
			ref.Version = uint64(p.Version)
			updated = true
		}
	}
	if !updated {
		refs = append(refs, &v1.CatalogRef{CatalogId: p.CatalogID, Version: uint64(p.Version)})
	}
	data, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	dir, err := execd.OpenDirectory(c.cache.StateDir, false, c.cache.StateOwner, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	return execd.AtomicWrite(dir, "loaded.json", data)
}

func (c *catalogs) pull(ctx context.Context, client allowopsv1connect.AgentServiceClient, notice *v1.CatalogAvailable) ([]*v1.CatalogLoadReport, error) {
	ref := notice.GetCatalog()
	if ref == nil || ref.CatalogId == "" || ref.Version == 0 || ref.Version > 1<<63-1 || len(notice.EnvelopeSha256) != sha256.Size || notice.EnvelopeSizeBytes == 0 || notice.EnvelopeSizeBytes > uint64(c.limits.CatalogBytes) {
		return nil, errors.New("INVALID_CATALOG_NOTICE")
	}
	report := &v1.CatalogLoadReport{Catalog: ref, ReportId: strconv.FormatInt(time.Now().UnixNano(), 10), FinalPage: true, Reason: "CATALOG_REJECTED"}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stream, err := client.PullCatalog(ctx, connect.NewRequest(&v1.PullCatalogRequest{Catalog: ref}))
	if err != nil {
		return []*v1.CatalogLoadReport{report}, nil
	}
	defer stream.Close()
	var data []byte
	eof := false
	for stream.Receive() {
		chunk := stream.Msg()
		if eof || !proto.Equal(ref, chunk.Catalog) || !bytes.Equal(notice.EnvelopeSha256, chunk.EnvelopeSha256) || chunk.Offset != uint64(len(data)) || len(chunk.Data) > c.limits.ChunkBytes || (len(chunk.Data) == 0 && !chunk.Eof) || uint64(len(data)+len(chunk.Data)) > notice.EnvelopeSizeBytes {
			return []*v1.CatalogLoadReport{report}, nil
		}
		data = append(data, chunk.Data...)
		eof = chunk.Eof
	}
	sum := sha256.Sum256(data)
	if stream.Err() != nil || !eof || uint64(len(data)) != notice.EnvelopeSizeBytes || !bytes.Equal(sum[:], notice.EnvelopeSha256) {
		return []*v1.CatalogLoadReport{report}, nil
	}
	c.install.Lock()
	defer c.install.Unlock()
	p, err := c.cache.Verify(data, ref.CatalogId, int64(ref.Version), time.Now())
	if err != nil {
		return []*v1.CatalogLoadReport{report}, nil
	}
	parent := filepath.Dir(execd.CatalogPath(c.cache.CatalogDir, p.CatalogID, p.Version))
	dir, err := execd.OpenDirectory(parent, true, c.cache.StateOwner, true)
	if err != nil {
		return []*v1.CatalogLoadReport{report}, nil
	}
	defer dir.Close()
	name := strconv.FormatInt(p.Version, 10) + ".dsse"
	previous, readErr := execd.ReadPrivateFile(dir, name, c.limits.CatalogBytes, c.cache.StateOwner)
	if readErr == nil && !bytes.Equal(previous, data) {
		report.Reason = "CATALOG_VERSION_CONFLICT"
		return []*v1.CatalogLoadReport{report}, nil
	}
	if readErr != nil && !os.IsNotExist(readErr) {
		return []*v1.CatalogLoadReport{report}, nil
	}
	if err := execd.AtomicWrite(dir, name, data); err != nil {
		return []*v1.CatalogLoadReport{report}, nil
	}
	if err := c.save(p); err != nil {
		return []*v1.CatalogLoadReport{report}, nil
	}
	c.put(p)
	report.Loaded = true
	report.Reason = ""
	names := make([]string, 0, len(p.Actions))
	for name := range p.Actions {
		names = append(names, name)
	}
	sort.Strings(names)
	var unsupported []*v1.UnsupportedAction
	for _, name := range names {
		a := p.Actions[name]
		support := catalog.CheckHost(a)
		if !support.Supported {
			unsupported = append(unsupported, &v1.UnsupportedAction{Action: name, Reason: "ACTION_UNSUPPORTED"})
		}
	}
	var reports []*v1.CatalogLoadReport
	for start := 0; start < max(1, len(unsupported)); start += 100 {
		page := proto.Clone(report).(*v1.CatalogLoadReport)
		page.PageIndex = uint32(start / 100)
		page.UnsupportedActions = unsupported[min(start, len(unsupported)):min(start+100, len(unsupported))]
		page.FinalPage = start+100 >= len(unsupported)
		reports = append(reports, page)
	}
	return reports, nil
}
