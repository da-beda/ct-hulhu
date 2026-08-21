package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

func TestCalculateRange(t *testing.T) {
	tests := []struct{name string; opts Options; treeSize,wantStart,wantEnd int64}{
		{"defaults fetch entire tree",Options{Start:-1},100000,0,100000},
		{"count limits entries",Options{Start:-1,Count:500},100000,0,500},
		{"explicit start",Options{Start:5000,Count:1000},100000,5000,6000},
		{"count clamped",Options{Start:-1,Count:200000},100000,0,100000},
		{"from-end count",Options{Start:-1,FromEnd:true,Count:5000},100000,95000,100000},
		{"from-end count exceeds tree",Options{Start:-1,FromEnd:true,Count:200000},100000,0,100000},
		{"from-end default",Options{Start:-1,FromEnd:true},100000,90000,100000},
		{"from-end small tree",Options{Start:-1,FromEnd:true},500,0,500},
		{"from-end explicit start",Options{Start:80000,FromEnd:true},100000,80000,100000},
	}
	for _,tt:=range tests{t.Run(tt.name,func(t *testing.T){r:=&Runner{opts:&tt.opts};start,end:=r.calculateRange(tt.treeSize);if start!=tt.wantStart||end!=tt.wantEnd{t.Fatalf("got (%d,%d), want (%d,%d)",start,end,tt.wantStart,tt.wantEnd)}})}
}

func TestStateFilePathsAreDigestBasedAndModeSeparated(t *testing.T){
	r:=&Runner{opts:&Options{StateDir:"/tmp/ct-hulhu"}}
	url:="https://ct.googleapis.com/logs/us1/argon2025h1/"
	digest:=sha256.Sum256([]byte(url));base:=hex.EncodeToString(digest[:])
	if got,want:=r.stateFilePath(url),filepath.Join("/tmp/ct-hulhu",base+".scrape.state.json");got!=want{t.Fatalf("scrape state path=%q want=%q",got,want)}
	if got,want:=r.monitorStateFilePath(url),filepath.Join("/tmp/ct-hulhu",base+".monitor.state.json");got!=want{t.Fatalf("monitor state path=%q want=%q",got,want)}
	if r.stateFilePath(url)==r.monitorStateFilePath(url){t.Fatal("scrape and monitor state paths must differ")}
}

func TestStateDigestAvoidsSanitizedURLCollision(t *testing.T){
	a:="https://example.com/a_b/"
	b:="https://example.com/a/b/"
	if stateDigest(a)==stateDigest(b){t.Fatal("distinct URLs collided in state digest")}
}

func TestTruncate(t *testing.T){tests:=[]struct{in string;n int;want string}{{"short",10,"short"},{"exactly10!",10,"exactly10!"},{"this is way too long",10,"this is .."},{"abc",1,"a"},{"abc",0,""},{"abc",2,"ab"}};for _,tt:=range tests{if got:=truncate(tt.in,tt.n);got!=tt.want{t.Errorf("truncate(%q,%d)=%q want %q",tt.in,tt.n,got,tt.want)}}}

func TestReadLinesFromFile(t *testing.T){path:=filepath.Join(t.TempDir(),"domains.txt");content:="example.com\n# comment\n  sub.example.com  \n\nother.com\n";if err:=os.WriteFile(path,[]byte(content),0o644);err!=nil{t.Fatal(err)};lines,err:=readLinesFromFile(path);if err!=nil{t.Fatal(err)};if len(lines)!=3||lines[0]!="example.com"||lines[1]!="sub.example.com"||lines[2]!="other.com"{t.Fatalf("unexpected lines: %#v",lines)}}
func TestReadLinesFromFile_NotFound(t *testing.T){if _,err:=readLinesFromFile("/nonexistent/file.txt");err==nil{t.Fatal("expected error")}}

func TestLoadSaveProgressV2(t *testing.T){
	dir:=t.TempDir();r:=&Runner{opts:&Options{StateDir:dir}};url:="https://ct.example.com/log/"
	p,err:=r.loadProgress(url);if err!=nil||p!=nil{t.Fatalf("initial progress=%#v err=%v",p,err)}
	source:=ctlog.EntrySource{Protocol:ctlog.ProtocolRFC6962,LogID:"id",LogURL:url}
	if err:=r.saveProgress(source,100000,"012345",1000,60000,50001);err!=nil{t.Fatal(err)}
	p,err=r.loadProgress(url);if err!=nil{t.Fatal(err)}
	if p==nil||p.Version!=2||p.Protocol!=ctlog.ProtocolRFC6962||p.LogID!="id"||p.RangeStart!=1000||p.RangeEnd!=60000||p.NextIndex!=50001||p.LastIndex!=50000||p.EntriesDone!=49001{t.Fatalf("unexpected progress: %#v",p)}
	if got,ok:=p.SafeResumeIndex(1000,60000);!ok||got!=50001{t.Fatalf("resume got=%d ok=%v",got,ok)}
}

func TestMonitorStateIsIndependentAndPrivate(t *testing.T){
	dir:=t.TempDir();r:=&Runner{opts:&Options{StateDir:dir}};source:=ctlog.EntrySource{Protocol:ctlog.ProtocolStaticCT,LogID:"id",LogURL:"https://monitor.example/",Verified:true}
	head:=&ctlog.TreeHead{TreeSize:120,RootHash:make([]byte,32),Verified:true}
	if err:=r.saveMonitorProgress(source,head,100,120);err!=nil{t.Fatal(err)}
	p,err:=r.loadMonitorProgress(source.LogURL);if err!=nil{t.Fatal(err)}
	if p==nil||p.RangeStart!=100||p.NextIndex!=120||p.TreeSize!=120||!p.Verified{t.Fatalf("unexpected monitor progress: %#v",p)}
	if scrape,err:=r.loadProgress(source.LogURL);err!=nil||scrape!=nil{t.Fatalf("monitor state leaked into scrape state: %#v err=%v",scrape,err)}
	info,err:=os.Stat(r.monitorStateFilePath(source.LogURL));if err!=nil{t.Fatal(err)};if info.Mode().Perm()&0o077!=0{t.Fatalf("monitor state mode=%o",info.Mode().Perm())}
}

func TestLoadProgress_CorruptFileFailsClosed(t *testing.T){dir:=t.TempDir();r:=&Runner{opts:&Options{StateDir:dir}};url:="https://ct.example.com/log/";path:=r.stateFilePath(url);if err:=os.WriteFile(path,[]byte("not json"),0o600);err!=nil{t.Fatal(err)};if p,err:=r.loadProgress(url);err==nil||p!=nil{t.Fatalf("expected corrupt state error, p=%#v err=%v",p,err)}}

func TestLoadProgress_RejectsMismatchedURL(t *testing.T){dir:=t.TempDir();r:=&Runner{opts:&Options{StateDir:dir}};url:="https://ct.example.com/log/";data,_:=json.Marshal(ctlog.ScrapeProgress{Version:2,LogURL:"https://other/",TreeSize:10,RangeStart:0,RangeEnd:10,NextIndex:5});if err:=os.WriteFile(r.stateFilePath(url),data,0o600);err!=nil{t.Fatal(err)};if _,err:=r.loadProgress(url);err==nil{t.Fatal("expected mismatch error")}}

func TestSaveProgress_CreatesPrivateState(t *testing.T){dir:=filepath.Join(t.TempDir(),"nested","state");r:=&Runner{opts:&Options{StateDir:dir}};source:=ctlog.EntrySource{Protocol:ctlog.ProtocolRFC6962,LogURL:"https://ct.example.com/"};if err:=r.saveProgress(source,1000,"root",0,1000,501);err!=nil{t.Fatal(err)};path:=r.stateFilePath(source.LogURL);data,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)};var p ctlog.ScrapeProgress;if err:=json.Unmarshal(data,&p);err!=nil{t.Fatal(err)};if p.NextIndex!=501||p.LastIndex!=500{t.Fatalf("progress=%#v",p)};info,err:=os.Stat(path);if err!=nil{t.Fatal(err)};if info.Mode().Perm()&0o077!=0{t.Fatalf("state mode=%o",info.Mode().Perm())}}

func TestSaveProgress_RejectsImpossibleBounds(t *testing.T){r:=&Runner{opts:&Options{StateDir:t.TempDir()}};source:=ctlog.EntrySource{Protocol:ctlog.ProtocolRFC6962,LogURL:"https://ct.example/"};if err:=r.saveProgress(source,100,"root",50,100,40);err==nil{t.Fatal("expected invalid bounds error")}}

func TestCollectDomains_FromOptions(t *testing.T){configureLogger(true,false,true);r:=&Runner{opts:&Options{Domain:stringSlice{"example.com","other.com"}}};if got:=r.collectDomains();len(got)!=2{t.Fatalf("got %#v",got)}}
func TestCollectDomains_FromFile(t *testing.T){configureLogger(true,false,true);path:=filepath.Join(t.TempDir(),"domains.txt");_ = os.WriteFile(path,[]byte("file-domain.com\n"),0o644);r:=&Runner{opts:&Options{Domain:stringSlice{"cli-domain.com"},DomainFile:path}};if got:=r.collectDomains();len(got)!=2{t.Fatalf("got %#v",got)}}
func TestStringSlice_Set(t *testing.T){var s stringSlice;if err:=s.Set("a.com, b.com, c.com");err!=nil{t.Fatal(err)};if len(s)!=3||s[0]!="a.com"||s[2]!="c.com"{t.Fatalf("unexpected %#v",s)}}
func TestStringSlice_SetEmpty(t *testing.T){var s stringSlice;_ = s.Set(",, ,");if len(s)!=0{t.Fatalf("unexpected %#v",s)}}
func TestStringSlice_String(t *testing.T){s:=stringSlice{"a.com","b.com"};if s.String()!="a.com,b.com"{t.Fatalf("got %q",s.String())}}

func TestGetVersion_StripsVPrefix(t *testing.T){orig:=version;defer func(){version=orig}();version="v1.2.3";if got:=getVersion();got!="1.2.3"{t.Fatalf("got %q",got)};version="1.2.3";if got:=getVersion();got!="1.2.3"{t.Fatalf("got %q",got)};version="";if got:=getVersion();got==""{t.Fatal("empty version")}}
