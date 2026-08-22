package loglist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

func TestTrustedMatchesUsableQualifiedAndReadOnly(t *testing.T) {
	states := []LogState{{Usable:&StateInfo{}},{Qualified:&StateInfo{}},{ReadOnly:&ReadOnlyInfo{}}}
	for _,state:=range states{if !matchesState(state,"trusted"){t.Fatalf("state %s should match trusted",currentState(state))}}
	if matchesState(LogState{Retired:&StateInfo{}},"trusted"){t.Fatal("retired must not match trusted")}
}

func TestFetchParsesTiledLogs(t *testing.T) {
	const body=`{"version":"89.13","log_list_timestamp":"2026-08-09T13:35:15Z","operators":[{"name":"Google","logs":[],"tiled_logs":[{"description":"ParcelYard","log_id":"bG9nLWlk","key":"a2V5","submission_url":"https://submit.example/","monitoring_url":"https://monitor.example/","mmd":60,"state":{"qualified":{"timestamp":"2026-06-19T19:00:00Z"}}}]}]}`
	srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){_,_=w.Write([]byte(body))}));defer srv.Close()
	ll,err:=NewFetcher(5*time.Second).Fetch(context.Background(),srv.URL);if err!=nil{t.Fatal(err)}
	if len(ll.Operators)!=1||len(ll.Operators[0].TiledLogs)!=1{t.Fatalf("tiled logs not parsed: %#v",ll)}
	desc:=FilterDescriptors(ll,"trusted");if len(desc)!=1{t.Fatalf("descriptors=%d",len(desc))}
	if desc[0].Protocol!=ctlog.ProtocolStaticCT||desc[0].SubmissionURL!="https://submit.example/"||desc[0].MonitoringURL!="https://monitor.example/"||desc[0].State!="qualified"{t.Fatalf("unexpected descriptor: %#v",desc[0])}
}

func TestFilterDescriptorsIncludesBothProtocols(t *testing.T){
	ll:=&LogList{Operators:[]Operator{{Name:"op",Logs:[]Log{{Description:"rfc",URL:"rfc.example/log",State:LogState{Usable:&StateInfo{}}}},TiledLogs:[]TiledLog{{Description:"static",SubmissionURL:"https://submit/",MonitoringURL:"https://monitor/",State:LogState{ReadOnly:&ReadOnlyInfo{}}}}}}}
	got:=FilterDescriptors(ll,"trusted");if len(got)!=2{t.Fatalf("got %d descriptors",len(got))};if got[0].Protocol!=ctlog.ProtocolRFC6962||got[1].Protocol!=ctlog.ProtocolStaticCT{t.Fatalf("protocols=%q,%q",got[0].Protocol,got[1].Protocol)}
}

func TestFetcherRejectsOversizedLogList(t *testing.T){
	srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){data:=make([]byte,maxLogListSize+1);for i:=range data{data[i]='x'};_,_=w.Write(data)}));defer srv.Close()
	if _,err:=NewFetcher(5*time.Second).Fetch(context.Background(),srv.URL);err==nil{t.Fatal("expected oversized log list error")}
}
