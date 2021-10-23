package segment

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

// FromInterfaces creates a new Segment from a sequence of interfaces. The
// interface slice is copied to prevent problems with shared slices.
func FromInterfaces(interfaces ...snet.PathInterface) Segment {
	var sb strings.Builder
	for _, iface := range interfaces {
		sb.WriteString(fmt.Sprintf(" %s#%d ", iface.IA, iface.ID))
	}
	return Literal{
		Interfaces:  append([]snet.PathInterface(nil), interfaces...),
		fingerprint: sb.String(),
	}
}

// FromString creates a new Segment from its string representation. This
// function is mainly intended for testing purposes and will panic if the
// provided string cannot be parsed into a valid segment.
func FromString(segstr string) Segment {
	fields := strings.Fields(segstr)
	length := len(fields) - 1
	iastrs := make([]string, length)
	idstrs := make([]string, length)
	for i := 0; i < length; i++ {
		if i%2 == 0 {
			iastrs[i] = fields[i]
			ids := strings.Split(fields[i+1], ">")
			idstrs[i], idstrs[i+1] = ids[0], ids[1]
		} else {
			iastrs[i] = fields[i+1]
		}
	}
	interfaces := make([]snet.PathInterface, length)
	var sb strings.Builder
	for i := 0; i < length; i++ {
		ia, err := addr.IAFromString(iastrs[i])
		if err != nil {
			panic(err)
		}
		id, err := strconv.Atoi(idstrs[i])
		if err != nil {
			panic(err)
		}
		interfaces[i] = snet.PathInterface{ID: common.IFIDType(id), IA: ia}
		sb.WriteString(fmt.Sprintf(" %s#%d ", ia, common.IFIDType(id)))
	}
	return Literal{Interfaces: interfaces, fingerprint: sb.String()}
}

// Literal implements the Segment interface.
type Literal struct {
	// Interfaces is the sequence of ingress-egress interfaces of which the
	// segment literal consists.
	Interfaces  []snet.PathInterface
	fingerprint string
}

func (l Literal) PathInterfaces() []snet.PathInterface {
	return append([]snet.PathInterface(nil), l.Interfaces...)
}

func (l Literal) SrcIA() addr.IA {
	return l.Interfaces[0].IA
}

func (l Literal) DstIA() addr.IA {
	return l.Interfaces[len(l.Interfaces)-1].IA
}

func (l Literal) Fingerprint() string {
	return l.fingerprint
}

func (l Literal) String() string {
	str := ""
	for i, iface := range l.Interfaces {
		if i == len(l.Interfaces)-1 {
			str += fmt.Sprintf(">%d %s", iface.ID, iface.IA)
		} else if i%2 == 0 {
			str += fmt.Sprintf("%s %d", iface.IA, iface.ID)
		} else if i%2 == 1 {
			str += fmt.Sprintf(">%d ", iface.ID)
		}
	}
	return str
}
