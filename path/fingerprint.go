package path

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
)

// Fingerprint creates a unique string representation of a segment based on its
// hop sequence. It is faster than snet.Fingerprint and truly unique.
func Fingerprint(spath snet.Path) string {
	var meta *snet.PathMetadata
	if p, ok := spath.(path.Path); ok { // optimized version
		meta = &p.Meta
	} else { // might copy metadata
		meta = spath.Metadata()
	}
	var sb strings.Builder
	for _, iface := range (*meta).Interfaces {
		sb.WriteString(fmt.Sprintf(" %s#%d ", iface.IA, iface.ID))
	}
	return sb.String()
}
