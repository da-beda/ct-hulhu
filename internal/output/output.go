package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

const maxDedup=1_000_000
type WriterOptions struct{Append bool}
type Writer struct{mu sync.Mutex;bw *bufio.Writer;closer io.Closer;jsonMode bool;fields string;seen map[string]struct{};dedupWarned bool;writeErr error}
func NewWriter(path string,jsonMode bool,fields string)(*Writer,error){return NewWriterWithOptions(path,jsonMode,fields,WriterOptions{})}
func NewWriterWithOptions(path string,jsonMode bool,fields string,opts WriterOptions)(*Writer,error){w:=&Writer{jsonMode:jsonMode,fields:fields,seen:map[string]struct{}{}};if path!=""{flags:=os.O_CREATE|os.O_WRONLY;if opts.Append{flags|=os.O_APPEND}else{flags|=os.O_TRUNC};f,err:=os.OpenFile(path,flags,0o600);if err!=nil{return nil,fmt.Errorf("opening output file: %w",err)};w.bw=bufio.NewWriter(io.MultiWriter(f,os.Stdout));w.closer=f}else{w.bw=bufio.NewWriter(os.Stdout)};return w,nil}
func(w *Writer)recordWriteErr(err error){if err!=nil&&w.writeErr==nil{w.writeErr=err}}
func(w *Writer)WriteResult(r *ctlog.CertResult){w.mu.Lock();defer w.mu.Unlock();if w.writeErr!=nil{return};if w.jsonMode{w.writeJSON(r);return};switch w.fields{case"domains":w.writeUnique("d:",r.Domains,true);case"ips":w.writeUnique("i:",r.IPs,false);case"emails":w.writeUnique("e:",r.Emails,true);case"certs":w.writeCertLine(r);case"all":w.writeUnique("d:",r.Domains,true);w.writeUnique("i:",r.IPs,false);w.writeUnique("e:",r.Emails,true);default:w.writeUnique("d:",r.Domains,true)}}
func(w *Writer)writeUnique(prefix string,items []string,sanitize bool){for _,item:=range items{key:=prefix+item;if _,ok:=w.seen[key];ok{continue};w.checkDedupLimit();if len(w.seen)<maxDedup{w.seen[key]=struct{}{}};if sanitize{item=Sanitize(item)};_,err:=fmt.Fprintln(w.bw,item);w.recordWriteErr(err);if w.writeErr!=nil{return}}}
func(w *Writer)identity(r *ctlog.CertResult,prefix string)string{id:=r.LogID;if id==""{id=r.LogURL};return fmt.Sprintf("%s:%s:%s:%d",prefix,r.Protocol,id,r.Index)}
func(w *Writer)writeCertLine(r *ctlog.CertResult){key:=w.identity(r,"c");if _,ok:=w.seen[key];ok{return};w.checkDedupLimit();if len(w.seen)<maxDedup{w.seen[key]=struct{}{}};_,err:=fmt.Fprintf(w.bw,"[%s] %s issuer=%s domains=%s\n",r.NotAfter.Format("2006-01-02"),Sanitize(r.CommonName),Sanitize(r.Issuer),Sanitize(strings.Join(r.Domains,",")));w.recordWriteErr(err)}
type JSONResult struct{Domains []string `json:"domains,omitempty"`;IPs []string `json:"ips,omitempty"`;Emails []string `json:"emails,omitempty"`;CommonName string `json:"cn,omitempty"`;Issuer string `json:"issuer,omitempty"`;NotBefore string `json:"not_before,omitempty"`;NotAfter string `json:"not_after,omitempty"`;Timestamp string `json:"timestamp,omitempty"`;Serial string `json:"serial,omitempty"`;IsPrecert bool `json:"is_precert"`;Protocol ctlog.Protocol `json:"protocol,omitempty"`;LogID string `json:"log_id,omitempty"`;LogURL string `json:"log_url,omitempty"`;Index int64 `json:"index"`;LeafHash string `json:"leaf_hash,omitempty"`;CertificateSHA256 string `json:"cert_sha256,omitempty"`;IssuerFingerprints []string `json:"issuer_fingerprints,omitempty"`}
func(w *Writer)writeJSON(r *ctlog.CertResult){key:=w.identity(r,"j");if _,ok:=w.seen[key];ok{return};w.checkDedupLimit();if len(w.seen)<maxDedup{w.seen[key]=struct{}{}};jr:=JSONResult{Domains:sanitizeSlice(r.Domains),IPs:r.IPs,Emails:sanitizeSlice(r.Emails),CommonName:Sanitize(r.CommonName),Issuer:Sanitize(r.Issuer),NotBefore:r.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),NotAfter:r.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),Serial:r.Serial,IsPrecert:r.IsPrecert,Protocol:r.Protocol,LogID:r.LogID,LogURL:r.LogURL,Index:r.Index,LeafHash:r.LeafHash,CertificateSHA256:r.CertificateSHA256,IssuerFingerprints:append([]string(nil),r.IssuerFingerprints...)};if !r.Timestamp.IsZero(){jr.Timestamp=r.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z")};data,err:=json.Marshal(jr);if err!=nil{w.recordWriteErr(err);return};if _,err:=w.bw.Write(data);err!=nil{w.recordWriteErr(err);return};w.recordWriteErr(w.bw.WriteByte('\n'))}
func(w *Writer)Close()error{w.mu.Lock();defer w.mu.Unlock();if w.bw!=nil{w.recordWriteErr(w.bw.Flush())};if w.closer!=nil{w.recordWriteErr(w.closer.Close())};return w.writeErr}
func(w *Writer)Flush()error{w.mu.Lock();defer w.mu.Unlock();if w.writeErr!=nil{return w.writeErr};w.recordWriteErr(w.bw.Flush());return w.writeErr}
func(w *Writer)Stats()int{w.mu.Lock();defer w.mu.Unlock();return len(w.seen)}
func(w *Writer)checkDedupLimit(){if len(w.seen)>=maxDedup&&!w.dedupWarned{w.dedupWarned=true;fmt.Fprintf(os.Stderr,"[WRN] deduplication limit reached (%d entries), duplicates may appear in output\n",maxDedup)}}
func sanitizeSlice(ss []string)[]string{out:=make([]string,len(ss));for i,s:=range ss{out[i]=Sanitize(s)};return out}
func Sanitize(s string)string{clean:=true;for i:=0;i<len(s);i++{if s[i]<0x20||s[i]==0x1b||s[i]==0x7f{clean=false;break}};if clean{return s};var b strings.Builder;b.Grow(len(s));i:=0;for i<len(s){if s[i]==0x1b{i++;if i>=len(s){continue};switch s[i]{case'[':i++;for i<len(s)&&s[i]>=0x20&&s[i]<=0x3f{i++};if i<len(s){i++};case']':i++;for i<len(s)&&s[i]!=0x07{if s[i]==0x1b&&i+1<len(s)&&s[i+1]=='\\'{i+=2;break};i++};if i<len(s)&&s[i]==0x07{i++};case'P','X','^','_':i++;for i<len(s){if s[i]==0x1b&&i+1<len(s)&&s[i+1]=='\\'{i+=2;break};i++}};continue};if s[i]<0x20||s[i]==0x7f{i++;continue};b.WriteByte(s[i]);i++};return b.String()}
