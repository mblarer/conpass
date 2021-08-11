package ipn

import (
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

type Initiator struct {
	SrcIA, DstIA addr.IA
	Filter       segment.Filter
}

func (agent Initiator) NegotiateOver(stream io.ReadWriter) ([]segment.Segment, error) {
	paths, err := appnet.QueryPaths(agent.DstIA)
	if err != nil {
		return nil, fmt.Errorf("failed to query paths: %s", err.Error())
	}
	log.Println("queried", len(paths), "different paths to", agent.DstIA)
	for _, path := range paths {
		fmt.Println(" ", path)
	}
	segments, err := segment.SplitPaths(paths)
	if err != nil {
		return nil, fmt.Errorf("failed to split paths: %s", err.Error())
	}
	log.Println("split paths into", len(segments), "different segments:")
	for _, segment := range segments {
		fmt.Println(" ", segment)
	}
	newsegs := agent.Filter.Filter(segments)
	log.Println(len(newsegs), "segments remaining after initial filtering:")
	for _, segment := range newsegs {
		fmt.Println(" ", segment)
	}
	oldsegs := []segment.Segment{}
	bytes := segment.EncodeSegments(newsegs, oldsegs)
	_, err = stream.Write(bytes)
	if err != nil {
		return nil, err
	}
	recvbuf := make([]byte, 64*1024)
	_, err = stream.Read(recvbuf)
	if err != nil {
		return nil, err
	}
	oldsegs = newsegs
	newsegs, err = segment.DecodeSegments(recvbuf, oldsegs)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	log.Println("the server replied with", len(newsegs), "segments:")
	for _, segment := range newsegs {
		fmt.Println(" ", segment)
	}
	newsegs = agent.Filter.Filter(segments)
	log.Println(len(newsegs), "segments remaining after final filtering:")
	for _, segment := range newsegs {
		fmt.Println(" ", segment)
	}
	newsegs = segment.SrcDstPaths(newsegs, agent.SrcIA, agent.DstIA)
	if err != nil {
		return nil, err
	}
	newpaths := make([]snet.Path, 0)
	// This is currently O(n*n), we can do it in O(n)
	for _, path := range paths {
		for _, seg := range newsegs {
			if string(snet.Fingerprint(path)) == segment.Fingerprint(seg) {
				newpaths = append(newpaths, path)
			}
		}
	}
	fmt.Println()
	log.Println("negotiated", len(newpaths), "paths in total:")
	for _, path := range newpaths {
		fmt.Println(" ", path)
	}
	return newsegs, nil
}
