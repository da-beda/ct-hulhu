package loglist

import (
	"strings"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

// CT log list v3 schema: https://www.gstatic.com/ct/log_list/v3/log_list_schema.json

type LogList struct {
	Version          string     `json:"version"`
	LogListTimestamp time.Time  `json:"log_list_timestamp,omitempty"`
	Operators        []Operator `json:"operators"`
}

type Operator struct {
	Name      string     `json:"name"`
	Email     []string   `json:"email"`
	Logs      []Log      `json:"logs"`
	TiledLogs []TiledLog `json:"tiled_logs"`
}

type Log struct {
	Description      string            `json:"description"`
	LogID            string            `json:"log_id"`
	Key              string            `json:"key"`
	URL              string            `json:"url"`
	DNS              string            `json:"dns"`
	MMD              int               `json:"mmd"`
	State            LogState          `json:"state"`
	TemporalInterval *TemporalInterval `json:"temporal_interval,omitempty"`
}

type TiledLog struct {
	Description      string            `json:"description"`
	LogID            string            `json:"log_id"`
	Key              string            `json:"key"`
	SubmissionURL    string            `json:"submission_url"`
	MonitoringURL    string            `json:"monitoring_url"`
	MMD              int               `json:"mmd"`
	State            LogState          `json:"state"`
	TemporalInterval *TemporalInterval `json:"temporal_interval,omitempty"`
}

type LogState struct {
	Usable    *StateInfo    `json:"usable,omitempty"`
	ReadOnly  *ReadOnlyInfo `json:"readonly,omitempty"`
	Retired   *StateInfo    `json:"retired,omitempty"`
	Qualified *StateInfo    `json:"qualified,omitempty"`
	Pending   *StateInfo    `json:"pending,omitempty"`
	Rejected  *StateInfo    `json:"rejected,omitempty"`
}

type StateInfo struct { Timestamp time.Time `json:"timestamp"` }
type ReadOnlyInfo struct { Timestamp time.Time `json:"timestamp"`; FinalTreeSize int64 `json:"final_tree_size"` }
type TemporalInterval struct { StartInclusive time.Time `json:"start_inclusive"`; EndExclusive time.Time `json:"end_exclusive"` }

func currentState(s LogState) string {
	switch {
	case s.Usable != nil: return "usable"
	case s.ReadOnly != nil: return "readonly"
	case s.Qualified != nil: return "qualified"
	case s.Retired != nil: return "retired"
	case s.Pending != nil: return "pending"
	case s.Rejected != nil: return "rejected"
	default: return "unknown"
	}
}

func matchesState(s LogState, filter string) bool {
	state := currentState(s)
	switch filter {
	case "all": return true
	case "trusted": return state == "usable" || state == "qualified" || state == "readonly"
	default: return state == filter
	}
}

func fullURL(value string) string {
	url := strings.TrimSpace(value)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") { url = "https://" + url }
	if url != "" && !strings.HasSuffix(url, "/") { url += "/" }
	return url
}

func (l *Log) CurrentState() string { return currentState(l.State) }
func (l *Log) MatchesState(filter string) bool { return matchesState(l.State, filter) }
func (l *Log) FullURL() string { return fullURL(l.URL) }

func (l *TiledLog) CurrentState() string { return currentState(l.State) }
func (l *TiledLog) MatchesState(filter string) bool { return matchesState(l.State, filter) }
func (l *TiledLog) FullSubmissionURL() string { return fullURL(l.SubmissionURL) }
func (l *TiledLog) FullMonitoringURL() string { return fullURL(l.MonitoringURL) }

type Descriptor struct {
	Operator      string
	Description   string
	LogID         string
	Key           string
	Protocol      ctlog.Protocol
	URL           string
	SubmissionURL string
	MonitoringURL string
	MMD           int
	State         string
}

func (d Descriptor) Source() ctlog.EntrySource {
	url := d.URL
	if d.Protocol == ctlog.ProtocolStaticCT { url = d.MonitoringURL }
	return ctlog.EntrySource{Protocol: d.Protocol, LogID: d.LogID, LogURL: url}
}
