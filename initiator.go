package ipn

import (
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
)

type Initiator struct {
	SrcIA    addr.IA
	DstIA    addr.IA
	Segments []segment.Segment
	Filter   segment.Filter
	Verbose  bool
}

func (agent Initiator) NegotiateOver(stream io.ReadWriter) ([]segment.Segment, error) {
	newsegs := agent.Filter.Filter(agent.Segments)
	if agent.Verbose {
		log.Println(len(newsegs), "segments remaining after initial filtering:")
		for _, segment := range newsegs {
			fmt.Println(" ", segment)
		}
	}
	oldsegs := []segment.Segment{}
	bytes, sentsegs := segment.EncodeSegments(newsegs, oldsegs, agent.SrcIA, agent.DstIA)
	_, err := stream.Write(bytes)
	if err != nil {
		return nil, err
	}
	recvbuf := make([]byte, 1<<20) // 1 MiB buffer
	_, err = stream.Read(recvbuf)
	if err != nil {
		return nil, err
	}
	newsegs, accsegs, _, _, err := segment.DecodeSegments(recvbuf, sentsegs)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	if agent.Verbose {
		log.Println("the server replied with", len(accsegs), "segments:")
		for _, segment := range accsegs {
			fmt.Println(" ", segment)
		}
	}
	newsegs = agent.Filter.Filter(accsegs)
	if agent.Verbose {
		log.Println(len(newsegs), "segments remaining after final filtering:")
		for _, segment := range newsegs {
			fmt.Println(" ", segment)
		}
	}
	return newsegs, nil
}
