package segment

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// Segment is an abstraction for any type that represents a sequence of path
// interfaces between a source AS and a destination AS.
type Segment interface {
	// PathInterfaces returns the sequence of path interfaces of which the
	// segment consists.
	PathInterfaces() []snet.PathInterface
	// SrcIA returns the segment's source ISD-AS address.
	SrcIA() addr.IA
	// DstIA returns the segment's destination ISD-AS address.
	DstIA() addr.IA
	// Fingerprint returns a string that uniquely identifies the segment.
	Fingerprint() string
	// Segment implements the fmt.Stringer interface.
	fmt.Stringer
}
