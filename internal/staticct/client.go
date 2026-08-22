package staticct

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

const maxStaticResponseSize = 64 << 20

type Client struct {
	submissionURL string
	monitoringURL string
	logID string
	httpClient *http.Client
	retries int
	treeSize atomic.Int64
	haveTree atomic.Bool
}

func NewClient(submissionURL,monitoringURL,logID string,timeout time.Duration,retries int)(*Client,error){
	submission,err:=normalizeURL(submissionURL);if err!=nil{return nil,fmt.Errorf("submission URL: %w",err)}
	monitoring,err:=normalizeURL(monitoringURL);if err!=nil{return nil,fmt.Errorf("monitoring URL: %w",err)}
	if _,err:=checkpointOrigin(submission);err!=nil{return nil,err}
	return &Client{submissionURL:submission,monitoringURL:monitoring,logID:logID,httpClient:&http.Client{Timeout:timeout,Transport:&http.Transport{MaxIdleConns:100,MaxIdleConnsPerHost:100,IdleConnTimeout:90*time.Second,TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},DisableCompression:true}},retries:retries},nil
}

func normalizeURL(raw string)(string,error){u,err:=url.Parse(strings.TrimSpace(raw));if err!=nil{return "",err};if u.Scheme!="http"&&u.Scheme!="https"{return "",fmt.Errorf("unsupported scheme %q",u.Scheme)};if u.Host==""{return "",fmt.Errorf("missing host")};if u.RawQuery!=""||u.Fragment!=""{return "",fmt.Errorf("query/fragment not allowed")};value:=u.String();if !strings.HasSuffix(value,"/"){value+="/"};return value,nil}

func(c *Client)Protocol()ctlog.Protocol{return ctlog.ProtocolStaticCT}
func(c *Client)Source()ctlog.EntrySource{return ctlog.EntrySource{Protocol:ctlog.ProtocolStaticCT,LogID:c.logID,LogURL:c.monitoringURL}}

func(c *Client)GetTreeHead(ctx context.Context)(*ctlog.TreeHead,error){body,err:=c.getWithRetry(ctx,c.monitoringURL+"checkpoint");if err!=nil{return nil,fmt.Errorf("checkpoint: %w",err)};cp,err:=ParseCheckpoint(body,c.submissionURL,c.logID);if err!=nil{return nil,err};c.treeSize.Store(cp.TreeSize);c.haveTree.Store(true);return cp.TreeHead(),nil}

func(c *Client)GetRawEntries(ctx context.Context,start,end int64)(*ctlog.GetEntriesResponse,error){
	if start<0||end<start{return nil,fmt.Errorf("invalid entry range [%d-%d]",start,end)}
	if !c.haveTree.Load(){if _,err:=c.GetTreeHead(ctx);err!=nil{return nil,err}}
	treeSize:=c.treeSize.Load();if end>=treeSize{return nil,fmt.Errorf("range end %d is outside checkpoint tree size %d",end,treeSize)}
	entries:=make([]ctlog.RawEntry,0,end-start+1)
	for current:=start;current<=end;{
		tileIndex:=uint64(current/tileWidth);tileStart:=int64(tileIndex*tileWidth);offset:=int(current-tileStart)
		width:=tileWidth
		fullTiles:=treeSize/tileWidth;remainder:=int(treeSize%tileWidth)
		if int64(tileIndex)==fullTiles&&remainder>0{width=remainder}
		path,err:=dataTilePath(tileIndex,width);if err!=nil{return nil,err}
		body,err:=c.getWithRetry(ctx,c.monitoringURL+path);if err!=nil{return nil,fmt.Errorf("data tile %d: %w",tileIndex,err)}
		tileEntries,err:=parseDataTile(body);if err!=nil{return nil,fmt.Errorf("data tile %d: %w",tileIndex,err)};if len(tileEntries)!=width{return nil,fmt.Errorf("data tile %d decoded %d entries, checkpoint requires %d",tileIndex,len(tileEntries),width)}
		remaining:=int(end-current+1);available:=width-offset;take:=min(remaining,available);entries=append(entries,tileEntries[offset:offset+take]...);current+=int64(take)
	}
	return &ctlog.GetEntriesResponse{Entries:entries},nil
}

func(c *Client)getWithRetry(ctx context.Context,target string)([]byte,error){var lastErr error;for attempt:=0;attempt<=c.retries;attempt++{if attempt>0{delay:=time.Duration(1<<uint(attempt-1))*time.Second;if delay>30*time.Second{delay=30*time.Second};select{case<-ctx.Done():return nil,ctx.Err();case<-time.After(delay):}};body,err:=c.get(ctx,target);if err==nil{return body,nil};lastErr=err};return nil,fmt.Errorf("all %d retries exhausted: %w",c.retries,lastErr)}

func(c *Client)get(ctx context.Context,target string)([]byte,error){req,err:=http.NewRequestWithContext(ctx,http.MethodGet,target,nil);if err!=nil{return nil,err};req.Header.Set("User-Agent","ct-hulhu");req.Header.Set("Accept-Encoding","gzip, identity");resp,err:=c.httpClient.Do(req);if err!=nil{return nil,err};defer resp.Body.Close();if resp.StatusCode!=http.StatusOK{return nil,fmt.Errorf("HTTP %d from %s",resp.StatusCode,target)}
	var reader io.Reader=resp.Body
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))){case "","identity":case "gzip":gz,err:=gzip.NewReader(resp.Body);if err!=nil{return nil,fmt.Errorf("opening gzip response: %w",err)};defer gz.Close();reader=gz;default:return nil,fmt.Errorf("unsupported content encoding %q",resp.Header.Get("Content-Encoding"))}
	body,err:=io.ReadAll(io.LimitReader(reader,maxStaticResponseSize+1));if err!=nil{return nil,err};if len(body)>maxStaticResponseSize{return nil,fmt.Errorf("response exceeds %d bytes",maxStaticResponseSize)};return body,nil}
