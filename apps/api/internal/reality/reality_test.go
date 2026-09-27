package reality

import "testing"

func TestUnsupportedTransport(t *testing.T) {
	r := ValidatePrerequisites(Request{Authorized: true, XrayPath: "/x", Transport: "tcp"})
	if r.State != PrerequisiteFailed {
		t.Fatalf("got %s", r.State)
	}
}
func TestNeverFakePass(t *testing.T) {
	r := ValidatePrerequisites(Request{Authorized: true, XrayPath: "/x", Transport: "raw"})
	if r.State == TestPassed {
		t.Fatal("prerequisite check must never fabricate a pass")
	}
}
