package segment

import (
	"github.com/mblarer/conpass/path"
	"github.com/scionproto/scion/go/lib/snet"
)

// Hash creates a string that uniquely identifies a segment with high
// probability solely based on the sequence of its path interfaces.
func Hash(segment Segment) string {
	path := path.InterfacePath{segment.PathInterfaces()}
	fingerprint := snet.Fingerprint(path)
	return string(fingerprint)
}
