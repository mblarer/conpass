package conpass

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
)

// Initiator represents a CONPASS agent in the initiator role.
type Initiator struct {
	// InitialSegset is the set of segments that is initially available to the
	// Initiator. It may be the result of querying the SCION daemon or it can
	// be set manually for testing, e.g., when no SCION daemon is available.
	InitialSegset segment.SegmentSet
	// Filter is the segment filter according to which the Initiator gives
	// consent to certain segments or combinations of segments.
	Filter segment.Filter
	// Verbose is a flag which makes the Initiator more verbose if true.
	Verbose bool
}

// NegotiateOver makes the Initiator negotiate consent over a given bytestream.
// If the negotiation is successful, the method returns the set of segments
// that have bilateral consent. Otherwise, an error is returned.
func (agent Initiator) NegotiateOver(stream io.ReadWriter) (segment.SegmentSet, error) {
	newsegset := agent.Filter.Filter(agent.InitialSegset)
	if agent.Verbose {
		log.Println(len(newsegset.Segments), "segments remaining after initial filtering:")
		for _, segment := range newsegset.Segments {
			fmt.Println(" ", segment)
		}
	}
	oldsegs := []segment.Segment{}
	bytes, sentsegs := segment.EncodeSegments(newsegset.Segments, oldsegs, newsegset.SrcIA, newsegset.DstIA)
	lenbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenbuf, uint32(len(bytes)))
	_, err := stream.Write(lenbuf)
	if err != nil {
		return segment.SegmentSet{}, err
	}
	_, err = stream.Write(bytes)
	if err != nil {
		return segment.SegmentSet{}, err
	}
	_, err = stream.Read(lenbuf)
	msglen := int(binary.BigEndian.Uint32(lenbuf))
	// TODO: handle too large or negative message lengths
	recvbuf := make([]byte, msglen)
	read := 0
	for err == nil && read < msglen {
		n, e := stream.Read(recvbuf[read:])
		read += n
		err = e
	}
	if err != nil && err != io.EOF {
		return segment.SegmentSet{}, err
	}
	_, accsegs, _, _, err := segment.DecodeSegments(recvbuf, sentsegs)
	if err != nil {
		return segment.SegmentSet{}, fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	if agent.Verbose {
		log.Println("the server replied with", len(accsegs), "segments:")
		for _, segment := range accsegs {
			fmt.Println(" ", segment)
		}
	}
	accsegset := segment.SegmentSet{
		Segments: accsegs,
		SrcIA:    agent.InitialSegset.SrcIA,
		DstIA:    agent.InitialSegset.DstIA,
	}
	newsegset = agent.Filter.Filter(accsegset)
	if agent.Verbose {
		log.Println(len(newsegset.Segments), "segments remaining after final filtering:")
		for _, segment := range newsegset.Segments {
			fmt.Println(" ", segment)
		}
	}
	return newsegset, nil
}
