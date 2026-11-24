//go:build !linux

package pluginhost

func openProjected(int, string) (int, error) {
	return -1, errProjected
}
