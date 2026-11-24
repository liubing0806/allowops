// Package standard registers the official gateway plugins.
package standard

import (
	_ "github.com/liubing0806/allowops/plugins/changes/allowops"
	_ "github.com/liubing0806/allowops/plugins/changes/httpfeed"
	_ "github.com/liubing0806/allowops/plugins/changes/k8srollout"
	_ "github.com/liubing0806/allowops/plugins/inventory/cmdbhttp"
	_ "github.com/liubing0806/allowops/plugins/inventory/hostlabels"
	_ "github.com/liubing0806/allowops/plugins/inventory/k8s"
	_ "github.com/liubing0806/allowops/plugins/inventory/promtargets"
	_ "github.com/liubing0806/allowops/plugins/inventory/static"
	_ "github.com/liubing0806/allowops/plugins/knowledge/gitdocs"
)
