package ctlog

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	sourceURL  string
	logID      string
	httpClient *http.Client
	retries    int
}

func NewClient(baseURL string, timeout time.Duration, retries int) *Client {
	return NewClientWithLogID(baseURL, "", timeout, retries)
}

func NewClientWithLogID(baseURL, logID string, timeout time.Duration, retries int) *Client {
	sourceURL := strings.TrimSpace(baseURL)
	requestBase := sourceURL
	if requestBase != "" && !strings.HasSuffix(requestBase, "/") { requestBase += "/" }
	return &Client{
		baseURL: requestBase, sourceURL: sourceURL, logID: logID,
		httpClient: &http.Client{Timeout: timeout, Transport: &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 100, IdleConnTimeout: 90*time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}},
		retries: retries,
	}
}

func (c *Client) Protocol() Protocol { return ProtocolRFC6962 }
func (c *Client) Source() EntrySource { return EntrySource{Protocol: ProtocolRFC6962, LogID: c.logID, LogURL: c.sourceURL} }

func (c *Client) GetTreeHead(ctx context.Context) (*TreeHead, error) {
	sth, err := c.GetSTH(ctx); if err != nil { return nil, err }
	root, err := base64.StdEncoding.DecodeString(sth.SHA256RootHash); if err != nil { return nil, fmt.Errorf("decoding STH root hash: %w",err) }; if len(root)!=32{return nil,fmt.Errorf("STH root hash has %d bytes, want 32",len(root))}
	sig, err := base64.StdEncoding.DecodeString(sth.TreeHeadSignature); if err != nil { return nil, fmt.Errorf("decoding STH signature: %w",err) }
	return &TreeHead{TreeSize:sth.TreeSize,Timestamp:sth.Timestamp,RootHash:root,Signature:sig},nil
}

func (c *Client) GetSTH(ctx context.Context) (*STH,error){
	body,err:=c.doRequestWithRetry(ctx,c.baseURL+"ct/v1/get-sth");if err!=nil{return nil,fmt.Errorf("get-sth: %w",err)}
	var sth STH;if err:=parseJSON(body,&sth,"STH");err!=nil{return nil,err};if sth.TreeSize<0{return nil,fmt.Errorf("STH contains negative tree size %d",sth.TreeSize)};return &sth,nil
}

func (c *Client) GetRawEntries(ctx context.Context,start,end int64)(*GetEntriesResponse,error){
	if start<0||end<start{return nil,fmt.Errorf("invalid entry range [%d-%d]",start,end)}
	url:=fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d",c.baseURL,start,end);body,err:=c.doRequestWithRetry(ctx,url);if err!=nil{return nil,fmt.Errorf("get-entries [%d-%d]: %w",start,end,err)}
	var resp GetEntriesResponse;if err:=parseJSON(body,&resp,fmt.Sprintf("entries [%d-%d]",start,end));err!=nil{return nil,err};return &resp,nil
}

func parseJSON(body []byte,target any,subject string)error{if err:=json.Unmarshal(body,target);err!=nil{return fmt.Errorf("parsing %s: %w",subject,err)};return nil}
func(c *Client)doRequestWithRetry(ctx context.Context,url string)([]byte,error){var lastErr error;for attempt:=0;attempt<=c.retries;attempt++{if err:=waitForRetryBackoff(ctx,attempt);err!=nil{return nil,err};body,err:=c.doRequest(ctx,url);if err==nil{return body,nil};lastErr=err};return nil,fmt.Errorf("all %d retries exhausted: %w",c.retries,lastErr)}
func waitForRetryBackoff(ctx context.Context,attempt int)error{if attempt<=0{return nil};backoff:=time.Duration(1<<uint(attempt-1))*time.Second;if backoff>30*time.Second{backoff=30*time.Second};select{case<-ctx.Done():return ctx.Err();case<-time.After(backoff):return nil}}
const maxResponseSize=64<<20
func(c *Client)doRequest(ctx context.Context,url string)([]byte,error){req,err:=http.NewRequestWithContext(ctx,http.MethodGet,url,nil);if err!=nil{return nil,err};req.Header.Set("User-Agent","ct-hulhu");resp,err:=c.httpClient.Do(req);if err!=nil{return nil,err};defer resp.Body.Close();if resp.StatusCode!=http.StatusOK{return nil,fmt.Errorf("HTTP %d from %s",resp.StatusCode,url)};body,err:=io.ReadAll(io.LimitReader(resp.Body,maxResponseSize+1));if err!=nil{return nil,err};if len(body)>maxResponseSize{return nil,fmt.Errorf("response from %s exceeds %d bytes",url,maxResponseSize)};return body,nil}
