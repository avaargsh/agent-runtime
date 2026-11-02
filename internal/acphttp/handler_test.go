package acphttp_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/acphttp"
	"github.com/avaargsh/agent-runtime/internal/run"
)

const (
	acpID = "spiffe://agent.example/ns/control/sa/agent-control-panel"
	intentID = "11111111-1111-4111-8111-111111111111"
)

type fakeStore struct {
	mu sync.Mutex
	receipts map[string]run.IntentReceipt
}

func (f *fakeStore) AcceptIntent(_ context.Context, request run.IntentStartRequest) (run.IntentReceipt,error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.receipts==nil { f.receipts=make(map[string]run.IntentReceipt) }
	if r,ok:=f.receipts[request.RunIntentID];ok {
		if r.TenantID!=request.TenantID || r.RequestDigest!=request.RequestDigest {return run.IntentReceipt{},run.ErrIdempotencyConflict}
		r.Created=false
		return r,nil
	}
	r:=run.IntentReceipt{TenantID:request.TenantID,RunIntentID:request.RunIntentID,RequestDigest:request.RequestDigest,RunID:"11111111-1111-4111-8111-222222222222",WorkflowID:"agent-run/v1/11111111-1111-4111-8111-222222222222",Created:true}
	f.receipts[request.RunIntentID]=r
	return r,nil
}
func (f *fakeStore) LookupIntent(_ context.Context,tenant,id,digest string)(run.IntentReceipt,error){
	f.mu.Lock()
	defer f.mu.Unlock()
	r,ok:=f.receipts[id]
	if !ok{return run.IntentReceipt{},run.ErrIntentNotFound}
	if r.TenantID!=tenant || r.RequestDigest!=digest{return run.IntentReceipt{},run.ErrIdempotencyConflict}
	r.Created=false
	return r,nil
}
func authorized(r *http.Request) {
	uri,_:=url.Parse(acpID)
	cert:=&x509.Certificate{URIs:[]*url.URL{uri}}
	r.TLS=&tls.ConnectionState{PeerCertificates:[]*x509.Certificate{cert},VerifiedChains:[][]*x509.Certificate{{cert}}}
}
func body() string {
	return `{"tenant_id":"t-1","run_intent_id":"`+intentID+`","request_digest":"sha256:`+strings.Repeat("a",64)+`","agent_id":"agent","agent_release_id":"rel","session_id":"s","input":{"message":"hello"}}`
}
func newHandler(t *testing.T)*httpHandler {
	t.Helper()
	st:=&fakeStore{}
	h,err:=acphttp.NewHandler(st,acpID)
	if err!=nil {t.Fatal(err)}
	return &httpHandler{h:h,store:st}
}
type httpHandler struct { h http.Handler; store *fakeStore }
func send(h http.Handler,method,path,payload string,verify bool)*httptest.ResponseRecorder {
	req:=httptest.NewRequest(method,path,strings.NewReader(payload))
	req.Header.Set("Content-Type","application/json")
	req.Header.Set("X-Forwarded-Client-Cert",acpID)
	if verify {authorized(req)}
	w:=httptest.NewRecorder();h.ServeHTTP(w,req);return w
}
func TestRequiresVerifiedMTLSNotSpoofableHeaders(t *testing.T){
	app:=newHandler(t)
	w:=send(app.h,http.MethodPost,"/internal/v1/run-intents:accept",body(),false)
	if w.Code!=http.StatusUnauthorized {t.Fatalf("spoofed header bypass: %d",w.Code)}
	r:=httptest.NewRequest(http.MethodPost,"/internal/v1/run-intents:accept",strings.NewReader(body()))
	r.Header.Set("Content-Type","application/json")
	r.TLS=&tls.ConnectionState{PeerCertificates:[]*x509.Certificate{{}},VerifiedChains:[][]*x509.Certificate{{{}}}}
	w=httptest.NewRecorder();app.h.ServeHTTP(w,r)
	if w.Code!=http.StatusUnauthorized {t.Fatalf("wrong peer bypass: %d",w.Code)}
	if _,err:=acphttp.NewHandler(nil,acpID);err==nil{t.Fatal("nil store should fail closed")}
	if _,err:=acphttp.NewHandler(app.store,"");err==nil{t.Fatal("empty identity should fail closed")}
}
func TestAcceptedRunReplaysAndCanBeInspected(t *testing.T){
	app:=newHandler(t)
	w:=send(app.h,http.MethodPost,"/internal/v1/run-intents:accept",body(),true)
	if w.Code!=http.StatusCreated{t.Fatalf("first accept=%d %s",w.Code,w.Body.String())}
	var receipt struct{ Status string `json:"status"`; RunID string `json:"run_id"`; WorkflowID string `json:"workflow_id"`; Created bool `json:"created"` }
	if err:=json.Unmarshal(w.Body.Bytes(),&receipt);err!=nil{t.Fatal(err)}
	if receipt.Status!="FOUND"||!receipt.Created||receipt.RunID==""||receipt.WorkflowID!="agent-run/v1/"+receipt.RunID{t.Fatalf("bad receipt %+v",receipt)}
	w=send(app.h,http.MethodPost,"/internal/v1/run-intents:accept",body(),true)
	if w.Code!=http.StatusOK{t.Fatalf("replay=%d %s",w.Code,w.Body.String())}
	path:="/internal/v1/run-intents/"+intentID+"?tenant_id=t-1&request_digest=sha256%3A"+strings.Repeat("a",64)
	w=send(app.h,http.MethodGet,path,"",true)
	if w.Code!=http.StatusOK||!strings.Contains(w.Body.String(),receipt.RunID){t.Fatalf("inspect=%d %s",w.Code,w.Body.String())}
}
func TestAbsentIsNotFinalAndConflictsAreNotRetried(t *testing.T){
	app:=newHandler(t)
	path:="/internal/v1/run-intents/"+intentID+"?tenant_id=t-1&request_digest=sha256%3A"+strings.Repeat("a",64)
	w:=send(app.h,http.MethodGet,path,"",true)
	if w.Code!=http.StatusOK||!strings.Contains(w.Body.String(),"\"ABSENT_UNCERTAIN\""){t.Fatalf("absence must be nonfinal: %d %s",w.Code,w.Body.String())}
	send(app.h,http.MethodPost,"/internal/v1/run-intents:accept",body(),true)
	changed:=strings.Replace(body(),"\"tenant_id\":\"t-1\"","\"tenant_id\":\"t-2\"",1)
	w=send(app.h,http.MethodPost,"/internal/v1/run-intents:accept",changed,true)
	if w.Code!=http.StatusConflict {t.Fatalf("conflict=%d %s",w.Code,w.Body.String())}
}
func TestRejectsDuplicateUnknownAndOversizeJSON(t *testing.T){
	app:=newHandler(t)
	cases:=[]string{
		strings.Replace(body(),"\"tenant_id\":\"t-1\"","\"tenant_id\":\"t-1\",\"tenant_id\":\"t-2\"",1),
		strings.Replace(body(),"\"message\":\"hello\"","\"message\":\"hello\",\"message\":\"bypass\"",1),
		strings.Replace(body(),"\"agent_id\":\"agent\"","\"agent_id\":\"agent\",\"extra\":1",1),
		strings.TrimSuffix(body(),"}")+" garbage",
		body()+strings.Repeat(" ",300000),
	}
	for i,raw:=range cases{
		w:=send(app.h,http.MethodPost,"/internal/v1/run-intents:accept",raw,true)
		if w.Code!=http.StatusBadRequest{t.Errorf("case %d status=%d %s",i,w.Code,w.Body.String())}
	}
	if len(app.store.receipts)!=0{t.Fatal("invalid request created Run")}
}
func TestRejectsUntrustedMethodQueryAndRawErrorLeak(t *testing.T) {
	app:=newHandler(t)
	w:=send(app.h,http.MethodGet,"/internal/v1/run-intents:accept","",true)
	if w.Code!=http.StatusMethodNotAllowed{t.Fatalf("method=%d",w.Code)}
	w=send(app.h,http.MethodGet,"/internal/v1/run-intents/"+intentID+"?tenant_id=t-1&tenant_id=t-2&request_digest=sha256%3A"+strings.Repeat("a",64),"",true)
	if w.Code!=http.StatusBadRequest{t.Fatalf("duplicate query=%d",w.Code)}
	if strings.Contains(w.Body.String(),"tenant-2"){t.Fatal("leaked raw input")}
}
