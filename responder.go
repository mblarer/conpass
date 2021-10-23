package conpass

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
)

// Responder represents a CONPASS agent in the responder role.
type Responder struct {
	// Filter is the segment filter according to which the Responder gives
	// consent to certain segments or combinations of segments.
	Filter segment.Filter
	// Verbose is a flag which makes the Responder more verbose if true.
	Verbose bool
}

// NegotiateOver makes the Responder negotiate consent over a given bytestream.
// If the negotiation is successful, the method returns the set of segments
// that have bilateral consent. Otherwise, an error is returned.
func (agent Responder) NegotiateOver(stream io.ReadWriter) (segment.SegmentSet, error) {
	lenbuf := make([]byte, 4)
	_, err := stream.Read(lenbuf)
	msglen := int(binary.BigEndian.Uint32(lenbuf))
	// TODO: handle too large or negative lengths
	recvbuffer := make([]byte, msglen)
	read := 0
	for err == nil && read < msglen {
		n, e := stream.Read(recvbuffer[read:])
		read += n
		err = e
	}
	if err != nil && err != io.EOF {
		return segment.SegmentSet{}, err
	}
	segsin, accsegs, srcIA, dstIA, err := segment.DecodeSegments(recvbuffer, []segment.Segment{})
	if err != nil {
		return segment.SegmentSet{}, err
	}
	if agent.Verbose {
		log.Println("request contains", len(segsin), "segments:")
		for _, segment := range segsin {
			fmt.Println(" ", segment)
		}
	}
	segsetout := agent.Filter.Filter(segment.SegmentSet{
		Segments: accsegs,
		SrcIA:    srcIA,
		DstIA:    dstIA,
	})
	if agent.Verbose {
		log.Println("responding with", len(segsetout.Segments), "segments:")
		for _, segment := range segsetout.Segments {
			fmt.Println(" ", segment)
		}
	}
	sendbuffer, _ := segment.EncodeSegments(segsetout.Segments, segsin, srcIA, dstIA)
	binary.BigEndian.PutUint32(lenbuf, uint32(len(sendbuffer)))
	_, err = stream.Write(lenbuf)
	if err != nil {
		return segment.SegmentSet{}, err
	}
	_, err = stream.Write(sendbuffer)
	if err != nil {
		return segment.SegmentSet{}, err
	}
	return segsetout, nil
}
