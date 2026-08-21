package staticct

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientReadsGzippedPartialDataTile(t *testing.T){
	logID:=base64.StdEncoding.EncodeToString(make([]byte,32));root:=make([]byte,32)
	var server *httptest.Server
	server=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		switch r.URL.Path{
		case "/monitor/checkpoint":
			_,_=w.Write(makeCheckpoint(t,server.URL+"/submit/",logID,2,root,111))
		case "/monitor/tile/data/000.p/2":
			if !strings.Contains(r.Header.Get("Accept-Encoding"),"gzip"){t.Errorf("missing gzip accept header")}
			var raw bytes.Buffer;gz:=gzip.NewWriter(&raw);_,_=gz.Write(append(x509TileLeaf([]byte{1},nil),x509TileLeaf([]byte{2},nil)...));_ = gz.Close();w.Header().Set("Content-Encoding","gzip");_,_=w.Write(raw.Bytes())
		default:http.NotFound(w,r)
		}
	}));defer server.Close()
	c,err:=NewClient(server.URL+"/submit/",server.URL+"/monitor/",logID,5*time.Second,0);if err!=nil{t.Fatal(err)}
	head,err:=c.GetTreeHead(context.Background());if err!=nil{t.Fatal(err)};if head.TreeSize!=2||c.Protocol()!="static-ct-api"{t.Fatalf("head=%#v protocol=%q",head,c.Protocol())}
	resp,err:=c.GetRawEntries(context.Background(),0,1);if err!=nil{t.Fatal(err)};if len(resp.Entries)!=2{t.Fatalf("entries=%d",len(resp.Entries))}
}

func TestClientSlicesAcrossDataTiles(t *testing.T){
	logID:=base64.StdEncoding.EncodeToString(make([]byte,32));root:=make([]byte,32)
	full:=make([]byte,0);for i:=0;i<256;i++{full=append(full,x509TileLeaf([]byte{byte(i)},nil)...)};partial:=append(x509TileLeaf([]byte{1},nil),x509TileLeaf([]byte{2},nil)...)
	var server *httptest.Server;server=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){switch r.URL.Path{case "/m/checkpoint":_,_=w.Write(makeCheckpoint(t,server.URL+"/s/",logID,258,root,1));case "/m/tile/data/000":_,_=w.Write(full);case "/m/tile/data/001.p/2":_,_=w.Write(partial);default:http.NotFound(w,r)}}));defer server.Close()
	c,err:=NewClient(server.URL+"/s/",server.URL+"/m/",logID,5*time.Second,0);if err!=nil{t.Fatal(err)};if _,err:=c.GetTreeHead(context.Background());err!=nil{t.Fatal(err)};resp,err:=c.GetRawEntries(context.Background(),255,257);if err!=nil{t.Fatal(err)};if len(resp.Entries)!=3{t.Fatalf("entries=%d",len(resp.Entries))}
}

func TestClientRejectsRangePastCheckpoint(t *testing.T){logID:=base64.StdEncoding.EncodeToString(make([]byte,32));var server *httptest.Server;server=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){_,_=w.Write(makeCheckpoint(t,server.URL+"/s/",logID,1,make([]byte,32),1))}));defer server.Close();c,err:=NewClient(server.URL+"/s/",server.URL+"/m/",logID,5*time.Second,0);if err!=nil{t.Fatal(err)};if _,err:=c.GetTreeHead(context.Background());err!=nil{t.Fatal(err)};if _,err:=c.GetRawEntries(context.Background(),0,1);err==nil{t.Fatal("expected range error")}}
