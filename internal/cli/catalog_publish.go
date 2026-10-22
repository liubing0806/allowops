package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/spf13/cobra"
)

func newPublishCmd() *cobra.Command {
	var file string
	var asJSON bool
	remote := &remoteFlags{}
	cmd := &cobra.Command{Use: "publish", Short: "Upload a signed catalog using a publisher service account token", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if remote.tokenEnv == "" {
			return errors.New("publish requires --token-env for a publisher service account token")
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 64<<20 {
			return errors.New("catalog envelope must be a regular file within 64 MiB")
		}
		raw, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
		if err != nil {
			return err
		}
		if len(raw) > 64<<20 {
			return errors.New("catalog envelope exceeds 64 MiB")
		}
		client, cfg, err := remote.client()
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		api := rpc.NewCatalogServiceClient(client, cfg.Gateway, connect.WithInterceptors(bearer(cfg.Token)))
		sum := sha256.Sum256(raw)
		begun, err := api.BeginCatalogUpload(c.Context(), connect.NewRequest(&v1.BeginCatalogUploadRequest{EnvelopeSizeBytes: uint64(len(raw)), EnvelopeSha256: sum[:]}))
		if err != nil {
			return rpcError(err)
		}
		chunk := int(begun.Msg.MaxChunkBytes)
		if chunk <= 0 || chunk > 64<<10 {
			return errors.New("invalid gateway chunk size")
		}
		for offset := 0; offset < len(raw); {
			end := min(offset+chunk, len(raw))
			r, err := api.UploadCatalogChunk(c.Context(), connect.NewRequest(&v1.UploadCatalogChunkRequest{UploadId: begun.Msg.UploadId, Offset: uint64(offset), Data: raw[offset:end]}))
			if err != nil {
				return rpcError(err)
			}
			if r.Msg.NextOffset != uint64(end) {
				return errors.New("gateway returned unexpected upload offset")
			}
			offset = end
		}
		published, err := api.PublishCatalog(c.Context(), connect.NewRequest(&v1.PublishCatalogRequest{UploadId: begun.Msg.UploadId}))
		if err != nil {
			return rpcError(err)
		}
		if asJSON {
			return outputProto(c, published.Msg)
		}
		w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "CATALOG\tVERSION\tACTIONS")
		fmt.Fprintf(w, "%s\t%d\t%d\n", published.Msg.Catalog.Catalog.CatalogId, published.Msg.Catalog.Catalog.Version, published.Msg.Catalog.ActionCount)
		return w.Flush()
	}}
	remote.flags(cmd)
	cmd.Flags().StringVarP(&file, "file", "f", "", "Signed DSSE envelope")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output JSON")
	return cmd
}
