package runner

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type stringSlice []string
func(s *stringSlice)String()string{return strings.Join(*s,",")}
func(s *stringSlice)Set(val string)error{for _,v:=range strings.Split(val,","){v=strings.TrimSpace(v);if v!=""{*s=append(*s,v)}};return nil}

type Options struct {
	Domain stringSlice; DomainFile string
	LogURL stringSlice; ListLogs bool; LogState string
	Workers int; ParseWorkers int; BatchSize int; RateLimit int; Timeout int; Retries int; Start int64; Count int64; FromEnd bool
	Output string; JSON bool; Fields string; Silent bool; Verbose bool; NoColor bool
	Monitor bool; PollInterval int
	Update bool; DisableUpdateCheck bool
	Resume bool; StateDir string
}

func ParseOptions()*Options{
	o:=&Options{}
	flag.Var(&o.Domain,"d","target domain(s) to filter (comma-separated, can be repeated)");flag.Var(&o.Domain,"domain","target domain(s) to filter (comma-separated, can be repeated)");flag.StringVar(&o.DomainFile,"df","","file containing target domains (one per line)")
	flag.Var(&o.LogURL,"lu","RFC6962 CT log URL(s) to scrape (comma-separated, can be repeated)");flag.Var(&o.LogURL,"log-url","RFC6962 CT log URL(s) to scrape (comma-separated, can be repeated)");flag.BoolVar(&o.ListLogs,"ls",false,"list available CT logs and exit");flag.BoolVar(&o.ListLogs,"list-logs",false,"list available CT logs and exit");flag.StringVar(&o.LogState,"log-state","trusted","filter logs by state (trusted/usable/readonly/retired/qualified/all)")
	flag.IntVar(&o.Workers,"w",4,"number of concurrent fetch workers");flag.IntVar(&o.Workers,"workers",4,"number of concurrent fetch workers");flag.IntVar(&o.ParseWorkers,"pw",0,"number of concurrent parse workers (0 = auto)");flag.IntVar(&o.ParseWorkers,"parse-workers",0,"number of concurrent parse workers (0 = auto)");flag.IntVar(&o.BatchSize,"bs",256,"entries per batch request");flag.IntVar(&o.BatchSize,"batch-size",256,"entries per batch request");flag.IntVar(&o.RateLimit,"rl",0,"max requests per second (0 = unlimited)");flag.IntVar(&o.RateLimit,"rate-limit",0,"max requests per second (0 = unlimited)");flag.IntVar(&o.Timeout,"to",30,"HTTP request timeout in seconds");flag.IntVar(&o.Timeout,"timeout",30,"HTTP request timeout in seconds");flag.IntVar(&o.Retries,"retries",3,"number of retries per failed request");flag.Int64Var(&o.Start,"start",-1,"start entry index (-1 = auto)");flag.Int64Var(&o.Count,"n",0,"number of entries to fetch (0 = all)");flag.Int64Var(&o.Count,"count",0,"number of entries to fetch (0 = all)");flag.BoolVar(&o.FromEnd,"from-end",false,"start from newest entries")
	flag.StringVar(&o.Output,"o","","output file path");flag.StringVar(&o.Output,"output","","output file path");flag.BoolVar(&o.JSON,"json",false,"JSON line output");flag.BoolVar(&o.JSON,"j",false,"JSON line output");flag.StringVar(&o.Fields,"f","domains","output fields (domains/ips/emails/certs/all)");flag.StringVar(&o.Fields,"fields","domains","output fields (domains/ips/emails/certs/all)");flag.BoolVar(&o.Silent,"s",false,"silent mode - only output results");flag.BoolVar(&o.Silent,"silent",false,"silent mode - only output results");flag.BoolVar(&o.Verbose,"v",false,"verbose output");flag.BoolVar(&o.Verbose,"verbose",false,"verbose output");flag.BoolVar(&o.NoColor,"nc",false,"disable color output");flag.BoolVar(&o.NoColor,"no-color",false,"disable color output")
	flag.BoolVar(&o.Monitor,"monitor",false,"continuous monitoring mode - watch for new entries");flag.BoolVar(&o.Monitor,"m",false,"continuous monitoring mode - watch for new entries");flag.IntVar(&o.PollInterval,"poll-interval",10,"seconds between tree-head polls in monitor mode");flag.IntVar(&o.PollInterval,"pi",10,"seconds between tree-head polls in monitor mode")
	flag.BoolVar(&o.Update,"up",false,"update ct-hulhu (disabled in this fork build)");flag.BoolVar(&o.Update,"update",false,"update ct-hulhu (disabled in this fork build)");flag.BoolVar(&o.DisableUpdateCheck,"duc",false,"disable automatic update check");flag.BoolVar(&o.DisableUpdateCheck,"disable-update-check",false,"disable automatic update check")
	flag.BoolVar(&o.Resume,"resume",false,"resume from last saved verified contiguous position");flag.StringVar(&o.StateDir,"state-dir",defaultStateDir(),"directory for state files")
	flag.Usage=func(){showBanner();fmt.Fprintln(os.Stderr,"Usage:\n  ct-hulhu [flags]\n\nAuto-discovery includes RFC6962 and Static CT logs. -lu is RFC6962-only.\n");printFlags()}
	flag.Parse();if flag.NArg()>0{fmt.Fprintf(os.Stderr,"error: unrecognized arguments: %s\n",strings.Join(flag.Args()," "));os.Exit(1)};configureLogger(o.Silent,o.Verbose,o.NoColor);o.validate();return o
}

func(o *Options)validate(){var es []string;if o.Workers<1||o.Workers>128{es=append(es,"-w/--workers must be between 1 and 128")};if o.ParseWorkers<0||o.ParseWorkers>128{es=append(es,"-pw/--parse-workers must be between 0 and 128")};if o.BatchSize<1||o.BatchSize>10000{es=append(es,"-bs/--batch-size must be between 1 and 10000")};if o.RateLimit<0{es=append(es,"-rl/--rate-limit must be >= 0")};if o.Timeout<1{es=append(es,"-to/--timeout must be >= 1")};if o.Retries<0||o.Retries>10{es=append(es,"--retries must be between 0 and 10")};if o.PollInterval<1{es=append(es,"-pi/--poll-interval must be >= 1")};validFields:=map[string]bool{"domains":true,"ips":true,"emails":true,"certs":true,"all":true};if !validFields[o.Fields]{es=append(es,fmt.Sprintf("-f/--fields invalid: %q",o.Fields))};validStates:=map[string]bool{"trusted":true,"usable":true,"readonly":true,"qualified":true,"retired":true,"all":true};if !validStates[o.LogState]{es=append(es,fmt.Sprintf("--log-state must be one of: trusted, usable, readonly, qualified, retired, all (got %q)",o.LogState))};if len(es)>0{for _,e:=range es{fmt.Fprintf(os.Stderr,"error: %s\n",e)};os.Exit(1)}}
func defaultStateDir()string{home,err:=os.UserHomeDir();if err!=nil{return ".ct-hulhu"};return filepath.Join(home,".ct-hulhu")}
func printFlags(){w:=os.Stderr;fmt.Fprintln(w,"\nLOG SELECTION:\n  -lu, -log-url string[]      explicit RFC6962 log URL(s)\n  -ls, -list-logs             list RFC6962 + Static CT logs\n  -log-state string           trusted=usable+qualified+readonly (default: trusted)\n\nSCRAPING:\n  -w, -workers int            concurrent fetch workers (default: 4)\n  -pw, -parse-workers int     concurrent parse workers, 0=auto\n  -bs, -batch-size int        entries per range request (default: 256)\n  -rl, -rate-limit int        max requests/sec, 0=unlimited\n  -to, -timeout int           HTTP timeout seconds (default: 30)\n  -retries int                retries per failed request (default: 3)\n  -start int                  start entry index\n  -n, -count int              entries to fetch, 0=all\n  -from-end                   start from newest entries\n\nMONITOR:\n  -m, -monitor                continuous monitoring\n  -pi, -poll-interval int     seconds between polls\n\nOUTPUT:\n  -o, -output string          output file\n  -j, -json                   JSON lines\n  -f, -fields string          domains/ips/emails/certs/all\n  -s, -silent                 results only\n  -v, -verbose                debug output\n  -nc, -no-color              disable color\n\nSTATE:\n  -resume                     resume from verified contiguous position\n  -state-dir string           state directory\n\nUPDATE:\n  -up, -update                disabled in fork build")}
