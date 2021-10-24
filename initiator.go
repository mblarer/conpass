package conpass

import (
	"fmt"
	"io"
	"log"

	"github.com/mblarer/conpass/segment"
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
	sentsegs, err := segment.WriteSegments(stream, newsegset.Segments, oldsegs, newsegset.SrcIA, newsegset.DstIA)
	_, accsegs, _, _, err := segment.ReadSegments(stream, sentsegs)
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
