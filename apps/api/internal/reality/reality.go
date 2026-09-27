package reality

import "fmt"

type State string

const (
	NotTested          State = "NOT_TESTED"
	CandidateOnly      State = "CANDIDATE_ONLY"
	PrerequisiteFailed State = "PREREQUISITE_FAILED"
	TestPassed         State = "TEST_PASSED"
	TestFailed         State = "TEST_FAILED"
)

var AllowedTransports = map[string]bool{"raw": true, "xhttp": true, "grpc": true}

type Request struct {
	Candidate    string
	OriginServer string
	XrayPath     string
	XrayVersion  string
	Transport    string
	Authorized   bool
}
type Result struct {
	State           State
	XrayVersion     string
	Transport       string
	HandshakeResult string
	FailureReason   string
}

func ValidatePrerequisites(r Request) Result {
	if !r.Authorized {
		return Result{State: PrerequisiteFailed, XrayVersion: r.XrayVersion, Transport: r.Transport, FailureReason: "authorized REALITY test not enabled"}
	}
	if !AllowedTransports[r.Transport] {
		return Result{State: PrerequisiteFailed, XrayVersion: r.XrayVersion, Transport: r.Transport, FailureReason: fmt.Sprintf("unsupported REALITY transport: %s", r.Transport)}
	}
	if r.XrayPath == "" {
		return Result{State: PrerequisiteFailed, XrayVersion: r.XrayVersion, Transport: r.Transport, FailureReason: "xray binary path is not configured"}
	}
	return Result{State: CandidateOnly, XrayVersion: r.XrayVersion, Transport: r.Transport, FailureReason: "prerequisites passed; actual authorized handshake harness is required before TEST_PASSED"}
}
