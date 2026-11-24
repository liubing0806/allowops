// Package standard registers the official gateway plugins.
package standard

import (
	_ "github.com/liubing0806/allowops/extensions/changes/allowops"
	_ "github.com/liubing0806/allowops/extensions/changes/httpfeed"
	_ "github.com/liubing0806/allowops/extensions/changes/k8srollout"
	_ "github.com/liubing0806/allowops/extensions/inventory/cmdbhttp"
	_ "github.com/liubing0806/allowops/extensions/inventory/hostlabels"
	_ "github.com/liubing0806/allowops/extensions/inventory/k8s"
	_ "github.com/liubing0806/allowops/extensions/inventory/promtargets"
	_ "github.com/liubing0806/allowops/extensions/inventory/static"
	_ "github.com/liubing0806/allowops/extensions/knowledge/gitdocs"
	_ "github.com/liubing0806/allowops/extensions/notifier/webhook"
)
