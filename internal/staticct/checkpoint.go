package staticct

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

type Checkpoint struct {
	Origin          string
	TreeSize        int64
	RootHash        []byte
	Timestamp       int64
	DigitallySigned []byte
	Raw             []byte
}

func checkpointOrigin(submissionURL string) (string,error) {
	u,err:=url.Parse(submissionURL);if err!=nil{return "",err}
	if u.Host==""||u.Scheme==""{return "",fmt.Errorf("submission URL must be absolute")}
	if u.RawQuery!=""||u.Fragment!=""{return "",fmt.Errorf("submission URL must not contain query or fragment")}
	path:=strings.TrimSuffix(u.EscapedPath(),"/")
	return u.Host+path,nil
}

func expectedNoteKeyID(origin,logID string)([4]byte,error){
	var out [4]byte
	id,err:=base64.StdEncoding.DecodeString(logID);if err!=nil{return out,fmt.Errorf("decoding log ID: %w",err)}
	if len(id)!=32{return out,fmt.Errorf("log ID has %d bytes, want 32",len(id))}
	payload:=make([]byte,0,len(origin)+1+1+32);payload=append(payload,origin...);payload=append(payload,'\n',0x05);payload=append(payload,id...)
	digest:=sha256.Sum256(payload);copy(out[:],digest[:4]);return out,nil
}

func ParseCheckpoint(data []byte,submissionURL,logID string)(*Checkpoint,error){
	if len(data)==0{return nil,fmt.Errorf("empty checkpoint")}
	text:=strings.TrimSuffix(string(data),"\n")
	lines:=strings.Split(text,"\n")
	if len(lines)<5{return nil,fmt.Errorf("checkpoint has %d lines, want at least 5",len(lines))}
	expectedOrigin,err:=checkpointOrigin(submissionURL);if err!=nil{return nil,err}
	if lines[0]!=expectedOrigin{return nil,fmt.Errorf("checkpoint origin %q does not match expected %q",lines[0],expectedOrigin)}
	size,err:=strconv.ParseUint(lines[1],10,63);if err!=nil{return nil,fmt.Errorf("parsing tree size: %w",err)}
	root,err:=base64.StdEncoding.DecodeString(lines[2]);if err!=nil{return nil,fmt.Errorf("decoding root hash: %w",err)};if len(root)!=32{return nil,fmt.Errorf("root hash has %d bytes, want 32",len(root))}
	if lines[3]!=""{return nil,fmt.Errorf("checkpoint extensions are not supported by Static CT v1.1")}
	keyID,err:=expectedNoteKeyID(expectedOrigin,logID);if err!=nil{return nil,err}

	var timestamp int64=-1
	var digitallySigned []byte
	for _,line:=range lines[4:]{
		if !strings.HasPrefix(line,"— "){continue}
		parts:=strings.SplitN(strings.TrimPrefix(line,"— ")," ",2);if len(parts)!=2||parts[0]!=expectedOrigin{continue}
		sig,err:=base64.StdEncoding.DecodeString(parts[1]);if err!=nil{continue};if len(sig)<4+8+4{continue}
		if string(sig[:4])!=string(keyID[:]){continue}
		ts:=binary.BigEndian.Uint64(sig[4:12]);if ts>math.MaxInt64{return nil,fmt.Errorf("checkpoint timestamp overflows int64")}
		timestamp=int64(ts);digitallySigned=append([]byte(nil),sig[12:]...);break
	}
	if timestamp<0{return nil,fmt.Errorf("checkpoint has no matching RFC6962 note signature")}
	return &Checkpoint{Origin:expectedOrigin,TreeSize:int64(size),RootHash:root,Timestamp:timestamp,DigitallySigned:digitallySigned,Raw:append([]byte(nil),data...)},nil
}

func (c *Checkpoint) TreeHead() *ctlog.TreeHead { return &ctlog.TreeHead{TreeSize:c.TreeSize,Timestamp:c.Timestamp,RootHash:append([]byte(nil),c.RootHash...),Signature:append([]byte(nil),c.DigitallySigned...),Checkpoint:append([]byte(nil),c.Raw...)} }
