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

type messageSizeReader struct {
	size   int
	reader io.Reader
}

func (r *messageSizeReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	r.size += n
	return
}

type doublepipe struct {
	io.Reader
	io.Writer
}

func main() {
	k, hops, enum := argsOrExit()

	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	msr1 := &messageSizeReader{reader: r1}
	msr2 := &messageSizeReader{reader: r2}
	p1 := doublepipe{msr1, w2}
	p2 := doublepipe{msr2, w1}

	srcIA, _ := addr.IAFromString("1-ffaa:0:1")
	core1, _ := addr.IAFromString("1-ffaa:0:1000")
	core2, _ := addr.IAFromString("2-ffaa:0:1")
	dstIA, _ := addr.IAFromString("2-ffaa:0:1000")

	segments := make([]segment.Segment, 0)
	segments = append(segments, internal.CreateSegments(k, hops, srcIA, core1)...)
	segments = append(segments, internal.CreateSegments(k, hops, core1, core2)...)
	segments = append(segments, internal.CreateSegments(k, hops, core2, dstIA)...)

	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}

	var cfilter, sfilter segment.Filter
	switch enum {
	case "n":
		cfilter = filter.FromFilters()
		sfilter = filter.FromFilters()
	case "c":
		cfilter = filter.SrcDstPathEnumerator()
		sfilter = filter.FromFilters()
	case "s":
		cfilter = filter.FromFilters()
		sfilter = filter.SrcDstPathEnumerator()
	}

	client := ipn.Initiator{
		InitialSegset: segset,
		Filter:        cfilter,
	}
	server := ipn.Responder{
		Filter: sfilter,
	}

	go func() { _, _ = server.NegotiateOver(p1) }()
	_, _ = client.NegotiateOver(p2)

	fmt.Println(msr1.size, msr2.size)
}

func argsOrExit() (int, int, string) {
	if len(os.Args) != 4 {
		usageAndExit()
	}
	k, err := strconv.Atoi(os.Args[1])
	if err != nil {
		usageAndExit()
	}
	hops, err := strconv.Atoi(os.Args[2])
	if err != nil {
		usageAndExit()
	}
	enum := os.Args[3]
	if enum != "n" && enum != "c" && enum != "s" {
		usageAndExit()
	}
	return k, hops, enum
}

func usageAndExit() {
	fmt.Println("wrong command line arguments:", os.Args[0], "k:int hops:int n|c|s")
	os.Exit(1)
}
