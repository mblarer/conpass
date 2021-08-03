package segment

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// Segment is an abstraction for any type that represents a sequence of path
// interfaces between a source AS and a destination AS.
type Segment interface {
	PathInterfaces() []snet.PathInterface
	SrcIA() addr.IA
	DstIA() addr.IA
}
