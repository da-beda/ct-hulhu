package staticct

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

const tileWidth = 256

func tileIndexPath(index uint64) string {
	s:=strconv.FormatUint(index,10)
	if rem:=len(s)%3;rem!=0{s=strings.Repeat("0",3-rem)+s}
	parts:=make([]string,0,len(s)/3)
	for i:=0;i<len(s);i+=3{part:=s[i:i+3];if i+3<len(s){part="x"+part};parts=append(parts,part)}
	return strings.Join(parts,"/")
}

func dataTilePath(index uint64,width int) (string,error) {
	if width<1||width>tileWidth{return "",fmt.Errorf("invalid data tile width %d",width)}
	path:="tile/data/"+tileIndexPath(index)
	if width<tileWidth{path+=fmt.Sprintf(".p/%d",width)}
	return path,nil
}

func readUint24(data []byte,pos *int)(int,error){if *pos+3>len(data){return 0,fmt.Errorf("truncated uint24")};n:=int(data[*pos])<<16|int(data[*pos+1])<<8|int(data[*pos+2]);*pos+=3;return n,nil}
func readOpaque24(data []byte,pos *int)([]byte,error){n,err:=readUint24(data,pos);if err!=nil{return nil,err};if n<=0{return nil,fmt.Errorf("zero-length opaque24")};if *pos+n>len(data){return nil,fmt.Errorf("truncated opaque24: need %d bytes, have %d",n,len(data)-*pos)};v:=data[*pos:*pos+n];*pos+=n;return v,nil}
func readOpaque16(data []byte,pos *int)([]byte,error){if *pos+2>len(data){return nil,fmt.Errorf("truncated uint16 length")};n:=int(binary.BigEndian.Uint16(data[*pos:*pos+2]));*pos+=2;if *pos+n>len(data){return nil,fmt.Errorf("truncated opaque16: need %d bytes, have %d",n,len(data)-*pos)};v:=data[*pos:*pos+n];*pos+=n;return v,nil}

func parseDataTile(data []byte)([]ctlog.RawEntry,error){
	var out []ctlog.RawEntry
	pos:=0
	for pos<len(data){
		entryStart:=pos
		if pos+10>len(data){return nil,fmt.Errorf("entry %d: truncated TimestampedEntry header",len(out))}
		pos+=8
		entryType:=binary.BigEndian.Uint16(data[pos:pos+2]);pos+=2
		var preCertWithLength []byte
		switch entryType{
		case 0:
			if _,err:=readOpaque24(data,&pos);err!=nil{return nil,fmt.Errorf("entry %d x509 signed_entry: %w",len(out),err)}
		case 1:
			if pos+32>len(data){return nil,fmt.Errorf("entry %d: truncated precert issuer hash",len(out))};pos+=32
			if _,err:=readOpaque24(data,&pos);err!=nil{return nil,fmt.Errorf("entry %d precert TBS: %w",len(out),err)}
		default:return nil,fmt.Errorf("entry %d: unknown log entry type %d",len(out),entryType)
		}
		if _,err:=readOpaque16(data,&pos);err!=nil{return nil,fmt.Errorf("entry %d extensions: %w",len(out),err)}
		timestampedEnd:=pos
		if entryType==1{
			preStart:=pos
			if _,err:=readOpaque24(data,&pos);err!=nil{return nil,fmt.Errorf("entry %d pre_certificate: %w",len(out),err)}
			preCertWithLength=append([]byte(nil),data[preStart:pos]...)
		}
		fingerprints,err:=readOpaque16(data,&pos);if err!=nil{return nil,fmt.Errorf("entry %d certificate_chain: %w",len(out),err)}
		if len(fingerprints)%32!=0{return nil,fmt.Errorf("entry %d certificate_chain length %d is not a multiple of 32",len(out),len(fingerprints))}
		issuerFingerprints:=make([]string,0,len(fingerprints)/32)
		for i:=0;i<len(fingerprints);i+=32{issuerFingerprints=append(issuerFingerprints,hex.EncodeToString(fingerprints[i:i+32]))}

		leaf:=make([]byte,0,2+timestampedEnd-entryStart);leaf=append(leaf,0,0);leaf=append(leaf,data[entryStart:timestampedEnd]...)
		var extra []byte
		if entryType==1{extra=append(extra,preCertWithLength...)}
		// RFC6962 extra_data uses a uint24 certificate-chain vector. The Static
		// data tile exposes issuer fingerprints instead of DER chain certificates;
		// preserve those separately and synthesize an empty DER chain because the
		// parser only requires the full pre_certificate above.
		extra=append(extra,0,0,0)
		out=append(out,ctlog.RawEntry{LeafInput:base64.StdEncoding.EncodeToString(leaf),ExtraData:base64.StdEncoding.EncodeToString(extra),IssuerFingerprints:issuerFingerprints})
	}
	return out,nil
}
