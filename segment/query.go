package segment

import (
	"fmt"

	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
)

// QuerySegments returns available segments between the local and remote ASes.
func QuerySegments(remoteIA addr.IA) ([]Segment, error) {
	paths, err := appnet.QueryPaths(remoteIA)
	if err != nil {
		return nil, fmt.Errorf("failed to query paths: %s", err.Error())
	}
	segments, err := SplitPaths(paths)
	if err != nil {
		return nil, fmt.Errorf("failed to split paths: %s", err.Error())
	}
	return segments, nil
}
