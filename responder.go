package conpass

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
)

type Responder struct {
	Filter  segment.Filter
	Verbose bool
}

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
