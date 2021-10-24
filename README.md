# CONPASS for SCION
This repository provides a Go package that SCION applications can use to leverage the CONPASS protocol for their communication.

The code can be tested by running `go test` in the repository root.

Examples on how to implement a CONPASS initiator (client) or responder (server) are provided in the [example](example) directory. Running a CONPASS initiator usually requires SCION connectivity, e.g., through a [SCIONLab](https://www.scionlab.org/) VM. Running a responder does not require SCION connectivity.
