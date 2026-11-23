package decision

import (
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
)

// A forged or stale Turn must never cross the model egress boundary even when
// its canonical Run/Tenant/Agent identity happens to match the stored Run.
// The trusted Runtime-issued TurnID comes from SecurityContext, not the Turn.
func TestInvokeRejectsMismatchedTrustedTurnBeforeAuditAndEgress(t *testing.T) {
	var requests atomic.Int32
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"ok"}`)
	})
	recorder := &boundaryAuditRecorder{}
	client := Client{Endpoint: url, Protector: passThroughProtector{}, Audit: recorder}

	turn := sample()
	turn.TurnID = "untrusted-stale-turn"
	got, err := client.Invoke(decisionAuditContext(t), turn, sampleIdentity())
	if !errors.Is(err, ErrRunIdentityMismatch) {
		t.Fatalf("Invoke() result=%+v error=%v, want ErrRunIdentityMismatch", got, err)
	}
	if requests.Load() != 0 || len(recorder.snapshot()) != 0 {
		t.Fatalf("mismatched Turn leaked to remote Decision/audit: requests=%d audits=%d",
			requests.Load(), len(recorder.snapshot()))
	}
}
