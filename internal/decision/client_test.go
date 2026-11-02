package decision

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sample() Turn {
	return Turn{ProtocolVersion: "v0.1", InvocationID:"inv-1", TenantID:"tenant-1", AgentID:"agent-1", RunID:"run-1", TurnID:"turn-1", UserInput:"hello"}
}

func TestInvokeFinal(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/decision-turns" { t.Error("unexpected path") }
		w.Header().Set("Content-Type","application/json")
		w.Write([]byte(`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final","text":"ok"}`))
	}))
	defer s.Close()
	out,err:= (Client{Endpoint:s.URL+"/api/v1/decision-turns"}).Invoke(context.Background(),sample())
	if err != nil || out.Text != "ok" { t.Fatalf("result=%+v err=%v",out,err) }
}

func TestWrongInvocationRejected(t *testing.T) {
	s:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		w.Write([]byte(`{"protocol_version":"v0.1","invocation_id":"wrong","kind":"final","text":"ok"}`))
	}))
	defer s.Close()
	_,err:=(Client{Endpoint:s.URL}).Invoke(context.Background(),sample())
	if err == nil { t.Fatal("expected invocation mismatch error") }
}

func TestUnsupportedVersionRejected(t *testing.T) {
	turn:=sample();turn.ProtocolVersion="v2"
	if err:=turn.Validate();err==nil { t.Fatal("expected version rejection") }
	turn=sample();turn.UserInput=strings.Repeat("x",4097)
	if err:=turn.Validate();err==nil { t.Fatal("expected size rejection") }
}
