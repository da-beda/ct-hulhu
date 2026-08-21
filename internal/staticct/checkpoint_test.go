package staticct

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func makeCheckpoint(t *testing.T,submissionURL,logID string,size uint64,root []byte,timestamp uint64)[]byte{
	t.Helper();origin,err:=checkpointOrigin(submissionURL);if err!=nil{t.Fatal(err)};keyID,err:=expectedNoteKeyID(origin,logID);if err!=nil{t.Fatal(err)}
	ds:=[]byte{4,3,0,1,0xaa};sig:=make([]byte,0,4+8+len(ds));sig=append(sig,keyID[:]...);ts:=make([]byte,8);binary.BigEndian.PutUint64(ts,timestamp);sig=append(sig,ts...);sig=append(sig,ds...)
	return []byte(origin+"\n"+itoa(size)+"\n"+base64.StdEncoding.EncodeToString(root)+"\n\n— "+origin+" "+base64.StdEncoding.EncodeToString(sig)+"\n")
}

func itoa(v uint64)string{if v==0{return "0"};var b [20]byte;i:=len(b);for v>0{i--;b[i]=byte('0'+v%10);v/=10};return string(b[i:])}

func TestParseCheckpoint(t *testing.T){id:=base64.StdEncoding.EncodeToString(make([]byte,32));root:=make([]byte,32);for i:=range root{root[i]=byte(i)};raw:=makeCheckpoint(t,"https://submit.example/2026h2/",id,513,root,123456);cp,err:=ParseCheckpoint(raw,"https://submit.example/2026h2/",id);if err!=nil{t.Fatal(err)};if cp.Origin!="submit.example/2026h2"||cp.TreeSize!=513||cp.Timestamp!=123456||string(cp.RootHash)!=string(root){t.Fatalf("unexpected checkpoint: %#v",cp)};head:=cp.TreeHead();if head.TreeSize!=513||len(head.Checkpoint)==0||len(head.Signature)==0{t.Fatalf("unexpected tree head: %#v",head)}}

func TestCheckpointRejectsOriginMismatch(t *testing.T){id:=base64.StdEncoding.EncodeToString(make([]byte,32));raw:=makeCheckpoint(t,"https://submit.example/a/",id,1,make([]byte,32),1);if _,err:=ParseCheckpoint(raw,"https://submit.example/b/",id);err==nil||!strings.Contains(err.Error(),"origin"){t.Fatalf("expected origin error, got %v",err)}}

func TestCheckpointRejectsWrongKeyID(t *testing.T){id:=base64.StdEncoding.EncodeToString(make([]byte,32));raw:=makeCheckpoint(t,"https://submit.example/a/",id,1,make([]byte,32),1);idx:=strings.LastIndex(string(raw)," ");if idx<0{t.Fatal("bad fixture")};bad:=append([]byte(nil),raw...);for i:=idx+1;i<len(bad)&&bad[i]!='\n';i++{if bad[i]>='A'&&bad[i]<='Z'{bad[i]='a';break}else if bad[i]>='a'&&bad[i]<='z'{bad[i]='A';break}};if _,err:=ParseCheckpoint(bad,"https://submit.example/a/",id);err==nil{t.Fatal("expected signature/key-id rejection")}}
