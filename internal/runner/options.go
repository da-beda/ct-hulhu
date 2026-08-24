package runner

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TheArqsz/ct-hulhu/internal/loglist"
)

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}

type Options struct {
	Domain     stringSlice
	DomainFile string

	LogURL        stringSlice
	ListLogs      bool
	LogState      string
	LogListOutput string

	Workers      int
	ParseWorkers int
	BatchSize    int
	RateLimit    int
	Timeout      int
	Retries      int
	Start        int64
	Count        int64
	FromEnd      bool

	Output          string
	MalformedOutput string
	JSON            bool
	Fields          string
	Silent          bool
	Verbose         bool
	NoColor         bool

	Monitor               bool
	PollInterval          int
	MonitorBaselineOutput string

	Update             bool
	DisableUpdateCheck bool

	Resume   bool
	StateDir string
}

func ParseOptions() *Options {
	o := &Options{}
	flag.Var(&o.Domain, "d", "target domain(s) to filter (comma-separated, can be repeated)")
	flag.Var(&o.Domain, "domain", "target domain(s) to filter (comma-separated, can be repeated)")
	flag.StringVar(&o.DomainFile, "df", "", "file containing target domains (one per line)")

	flag.Var(&o.LogURL, "lu", "RFC6962 CT log URL(s) to scrape (comma-separated, can be repeated)")
	flag.Var(&o.LogURL, "log-url", "RFC6962 CT log URL(s) to scrape (comma-separated, can be repeated)")
	flag.BoolVar(&o.ListLogs, "ls", false, "list available CT logs and exit")
	flag.BoolVar(&o.ListLogs, "list-logs", false, "list available CT logs and exit")
	flag.StringVar(&o.LogState, "log-state", "trusted", "filter logs by state (trusted/usable/readonly/retired/qualified/all)")
	flag.StringVar(&o.LogListOutput, "log-list-output", "", "write the exact auto-discovery log-list response bytes to this file")

	flag.IntVar(&o.Workers, "w", 4, "number of concurrent fetch workers")
	flag.IntVar(&o.Workers, "workers", 4, "number of concurrent fetch workers")
	flag.IntVar(&o.ParseWorkers, "pw", 0, "number of concurrent parse workers (0 = auto)")
	flag.IntVar(&o.ParseWorkers, "parse-workers", 0, "number of concurrent parse workers (0 = auto)")
	flag.IntVar(&o.BatchSize, "bs", 256, "entries per batch request")
	flag.IntVar(&o.BatchSize, "batch-size", 256, "entries per batch request")
	flag.IntVar(&o.RateLimit, "rl", 0, "max requests per second (0 = unlimited)")
	flag.IntVar(&o.RateLimit, "rate-limit", 0, "max requests per second (0 = unlimited)")
	flag.IntVar(&o.Timeout, "to", 30, "HTTP request timeout in seconds")
	flag.IntVar(&o.Timeout, "timeout", 30, "HTTP request timeout in seconds")
	flag.IntVar(&o.Retries, "retries", 3, "number of retries per failed request")
	flag.Int64Var(&o.Start, "start", -1, "start entry index (-1 = auto)")
	flag.Int64Var(&o.Count, "n", 0, "number of entries to fetch (0 = all)")
	flag.Int64Var(&o.Count, "count", 0, "number of entries to fetch (0 = all)")
	flag.BoolVar(&o.FromEnd, "from-end", false, "start from newest entries")

	flag.StringVar(&o.Output, "o", "", "output file path")
	flag.StringVar(&o.Output, "output", "", "output file path")
	flag.StringVar(&o.MalformedOutput, "malformed-output", "", "malformed-entry evidence JSONL path (default: <output>.malformed.jsonl or state-dir/malformed.jsonl)")
	flag.BoolVar(&o.JSON, "json", false, "JSON line output")
	flag.BoolVar(&o.JSON, "j", false, "JSON line output")
	flag.StringVar(&o.Fields, "f", "domains", "output fields (domains/ips/emails/certs/all)")
	flag.StringVar(&o.Fields, "fields", "domains", "output fields (domains/ips/emails/certs/all)")
	flag.BoolVar(&o.Silent, "s", false, "silent mode - only output results")
	flag.BoolVar(&o.Silent, "silent", false, "silent mode - only output results")
	flag.BoolVar(&o.Verbose, "v", false, "verbose output")
	flag.BoolVar(&o.Verbose, "verbose", false, "verbose output")
	flag.BoolVar(&o.NoColor, "nc", false, "disable color output")
	flag.BoolVar(&o.NoColor, "no-color", false, "disable color output")

	flag.BoolVar(&o.Monitor, "monitor", false, "continuous monitoring mode - watch for new entries")
	flag.BoolVar(&o.Monitor, "m", false, "continuous monitoring mode - watch for new entries")
	flag.IntVar(&o.PollInterval, "poll-interval", 10, "seconds between tree-head polls in monitor mode")
	flag.IntVar(&o.PollInterval, "pi", 10, "seconds between tree-head polls in monitor mode")
	flag.StringVar(&o.MonitorBaselineOutput, "monitor-baseline-output", "", "write newly initialized monitor-state files before the first delta poll")

	flag.BoolVar(&o.Update, "up", false, "update ct-hulhu (disabled in this fork build)")
	flag.BoolVar(&o.Update, "update", false, "update ct-hulhu (disabled in this fork build)")
	flag.BoolVar(&o.DisableUpdateCheck, "duc", false, "disable automatic update check")
	flag.BoolVar(&o.DisableUpdateCheck, "disable-update-check", false, "disable automatic update check")

	flag.BoolVar(&o.Resume, "resume", false, "resume from last saved verified contiguous position")
	flag.StringVar(&o.StateDir, "state-dir", defaultStateDir(), "directory for state files")

	flag.Usage = func() {
		showBanner()
		fmt.Fprint(os.Stderr, "Usage:\n  ct-hulhu [flags]\n\nAuto-discovery includes RFC6962 and Static CT logs. -lu is RFC6962-only.\n\n")
		printFlags()
	}
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "error: unrecognized arguments: %s\n", strings.Join(flag.Args(), " "))
		os.Exit(1)
	}
	configureLogger(o.Silent, o.Verbose, o.NoColor)
	o.validate()
	loglist.SetEvidenceOutput(o.LogListOutput)
	return o
}

func canonicalOptionPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

func optionPathWithin(root, candidate string) bool {
	if root == "" || candidate == "" {
		return false
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)))
}

func (o *Options) validate() {
	var problems []string
	if o.Workers < 1 || o.Workers > 128 {
		problems = append(problems, "-w/--workers must be between 1 and 128")
	}
	if o.ParseWorkers < 0 || o.ParseWorkers > 128 {
		problems = append(problems, "-pw/--parse-workers must be between 0 and 128")
	}
	if o.BatchSize < 1 || o.BatchSize > 10000 {
		problems = append(problems, "-bs/--batch-size must be between 1 and 10000")
	}
	if o.RateLimit < 0 {
		problems = append(problems, "-rl/--rate-limit must be >= 0")
	}
	if o.Timeout < 1 {
		problems = append(problems, "-to/--timeout must be >= 1")
	}
	if o.Retries < 0 || o.Retries > 10 {
		problems = append(problems, "--retries must be between 0 and 10")
	}
	if o.PollInterval < 1 {
		problems = append(problems, "-pi/--poll-interval must be >= 1")
	}
	validFields := map[string]bool{"domains": true, "ips": true, "emails": true, "certs": true, "all": true}
	if !validFields[o.Fields] {
		problems = append(problems, fmt.Sprintf("-f/--fields invalid: %q", o.Fields))
	}
	validStates := map[string]bool{"trusted": true, "usable": true, "readonly": true, "qualified": true, "retired": true, "all": true}
	if !validStates[o.LogState] {
		problems = append(problems, fmt.Sprintf("--log-state must be one of: trusted, usable, readonly, qualified, retired, all (got %q)", o.LogState))
	}
	if o.LogListOutput != "" {
		if len(o.LogURL) > 0 {
			problems = append(problems, "-log-list-output requires auto-discovery and cannot be combined with -lu/--log-url")
		}
		logListPath, err := canonicalOptionPath(o.LogListOutput)
		if err != nil {
			problems = append(problems, fmt.Sprintf("invalid -log-list-output path: %v", err))
		} else {
			for label, candidate := range map[string]string{
				"normal output":           o.Output,
				"malformed output":        o.MalformedOutput,
				"monitor baseline output": o.MonitorBaselineOutput,
			} {
				other, otherErr := canonicalOptionPath(candidate)
				if otherErr != nil {
					problems = append(problems, fmt.Sprintf("invalid %s path: %v", label, otherErr))
					continue
				}
				if other != "" && other == logListPath {
					problems = append(problems, fmt.Sprintf("-log-list-output must be distinct from %s", label))
				}
			}
		}
	}
	if o.MonitorBaselineOutput != "" {
		if !o.Monitor {
			problems = append(problems, "-monitor-baseline-output is valid only with -m/--monitor")
		}
		if !o.Resume {
			problems = append(problems, "-monitor-baseline-output requires -resume")
		}
		baselinePath, err := canonicalOptionPath(o.MonitorBaselineOutput)
		if err != nil {
			problems = append(problems, fmt.Sprintf("invalid -monitor-baseline-output path: %v", err))
		} else {
			for label, candidate := range map[string]string{
				"normal output":    o.Output,
				"malformed output": o.MalformedOutput,
				"log-list output":  o.LogListOutput,
			} {
				other, otherErr := canonicalOptionPath(candidate)
				if otherErr != nil {
					problems = append(problems, fmt.Sprintf("invalid %s path: %v", label, otherErr))
					continue
				}
				if other != "" && other == baselinePath {
					problems = append(problems, fmt.Sprintf("-monitor-baseline-output must be distinct from %s", label))
				}
			}
			statePath, stateErr := canonicalOptionPath(o.StateDir)
			if stateErr != nil {
				problems = append(problems, fmt.Sprintf("invalid state directory: %v", stateErr))
			} else if optionPathWithin(statePath, baselinePath) {
				problems = append(problems, "-monitor-baseline-output must be outside -state-dir")
			}
		}
	}
	if len(problems) > 0 {
		for _, problem := range problems {
			fmt.Fprintf(os.Stderr, "error: %s\n", problem)
		}
		os.Exit(1)
	}
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ct-hulhu"
	}
	return filepath.Join(home, ".ct-hulhu")
}

func printFlags() {
	w := os.Stderr
	fmt.Fprintln(w, "\nTARGET:\n  -d, -domain string[]        target domain(s)\n  -df string                  file containing target domains")
	fmt.Fprintln(w, "\nLOG SELECTION:\n  -lu, -log-url string[]      explicit RFC6962 log URL(s)\n  -ls, -list-logs             list RFC6962 + Static CT logs\n  -log-state string           trusted=usable+qualified+readonly (default: trusted)\n  -log-list-output string     persist exact auto-discovery log-list bytes")
	fmt.Fprintln(w, "\nSCRAPING:\n  -w, -workers int            concurrent fetch workers (default: 4)\n  -pw, -parse-workers int     concurrent parse workers, 0=auto\n  -bs, -batch-size int        entries per range request (default: 256)\n  -rl, -rate-limit int        max requests/sec, 0=unlimited\n  -to, -timeout int           HTTP timeout seconds (default: 30)\n  -retries int                retries per failed request (default: 3)\n  -start int                  start entry index\n  -n, -count int              entries to fetch, 0=all\n  -from-end                   start from newest entries")
	fmt.Fprintln(w, "\nMONITOR:\n  -m, -monitor                continuous monitoring\n  -pi, -poll-interval int     seconds between polls\n  -monitor-baseline-output    persist newly initialized state before the first delta poll")
	fmt.Fprintln(w, "\nOUTPUT:\n  -o, -output string          output file\n  -malformed-output string    malformed-entry evidence JSONL\n  -j, -json                   JSON lines\n  -f, -fields string          domains/ips/emails/certs/all\n  -s, -silent                 results only\n  -v, -verbose                debug output\n  -nc, -no-color              disable color")
	fmt.Fprintln(w, "\nSTATE:\n  -resume                     resume from selection-bound contiguous position\n  -state-dir string           state directory")
	fmt.Fprintln(w, "\nUPDATE:\n  -up, -update                disabled in fork build")
}
