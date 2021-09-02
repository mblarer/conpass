package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/mblarer/scion-ipn"
	"github.com/mblarer/scion-ipn/filter"
	"github.com/mblarer/scion-ipn/internal"
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
)

type doublepipe struct {
	*io.PipeReader
	*io.PipeWriter
}

func main() {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	p1, p2 := doublepipe{r1,w2}, doublepipe{r2,w1}

	k, hops := argsOrExit()

	srcIA, _ := addr.IAFromString("1-ffaa:0:1")
	core1, _ := addr.IAFromString("1-ffaa:0:1000")
	core2, _ := addr.IAFromString("2-ffaa:0:1")
	dstIA, _ := addr.IAFromString("2-ffaa:0:1000")

	segments := make([]segment.Segment, 0)
	segments = append(segments, internal.CreateSegments(k, hops, srcIA, core1)...)
	segments = append(segments, internal.CreateSegments(k, hops, core1, core2)...)
	segments = append(segments, internal.CreateSegments(k, hops, core2, dstIA)...)

	client := ipn.Initiator{
		SrcIA: srcIA,
		DstIA: dstIA,
		Segments: segments,
		Filter: filter.FromFilters(),
		PrintMsgSize: true,
	}
	server := ipn.Responder{
		Filter: filter.FromFilters(),
	}

	go func() { _, _ = server.NegotiateOver(p1) }()
	_, _ = client.NegotiateOver(p2)
}

func argsOrExit() (int, int) {
	if len(os.Args) != 3 {
		fmt.Println("wrong command line arguments:", os.Args[0], "<k:int>", "<hops:int>")
		os.Exit(1)
	}
	k, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("wrong command line arguments:", os.Args[0], "<k:int>", "<hops:int>")
		os.Exit(1)
	}
	hops, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("wrong command line arguments:", os.Args[0], "<k:int>", "<hops:int>")
		os.Exit(1)
	}
	return k, hops
}
