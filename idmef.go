package idmef

import (
	"encoding/xml"
	"time"

	"github.com/grokify/go-idmef/ntp"
)

const (
	XMLNSIDMEFURL     = "http://iana.org/idmef"
	XMLNSIDMEFVersion = "1.0"
)

// Message is for authoring. For parsing use
// `github.com/grokify/go-idmef/unmarshal/Message`.
type Message struct {
	XMLName    xml.Name   `xml:"idmef:IDMEF-Message"`
	XMLNSIDMEF string     `xml:"xmlns:idmef,attr"`
	Version    string     `xml:"version,attr"`
	Alert      *Alert     `xml:"idmef:Alert"`
	Heartbeat  *Heartbeat `xml:"idmef:Heartbeat"`
}

func (m *Message) Bytes(prefix, indent string) ([]byte, error) {
	if prefix == "" && indent == "" {
		return xml.Marshal(m)
	}
	return xml.MarshalIndent(m, prefix, indent)
}

type Alert struct {
	MessageID        string            `xml:"messageid,attr,omitempty"`
	Analyzer         Analyzer          `xml:"idmef:Analyzer"`       // Exactly one.
	CreateTime       Time              `xml:"idmef:CreateTime"`     // Exactly one.
	DetectTime       *Time             `xml:"idmef:DetectTime"`     // Zero or one
	AnalyzerTime     *Time             `xml:"idmef:AnalyzerTime"`   // Zero or one.
	Source           []Source          `xml:"idmef:Source"`         // Zero or more.
	Target           []Target          `xml:"idmef:Target"`         // Zero or more.
	Classification   Classification    `xml:"idmef:Classification"` // Exactly one.
	Assessment       *Assessment       `xml:"idmef:Assessment"`
	CorrelationAlert *CorrelationAlert `xml:"idmef:CorrelationAlert"` // Zero or one.
	AdditionalData   []AdditionalData  `xml:"idmef:AdditionalData"`
}

type Heartbeat struct {
	MessageID      string           `xml:"messageid,attr,omitempty"`
	Analyzer       Analyzer         `xml:"idmef:Analyzer"`   // Exactly one.
	CreateTime     Time             `xml:"idmef:CreateTime"` // Exactly one.
	AdditionalData []AdditionalData `xml:"idmef:AdditionalData"`
}

// Analyzer class identifies the analyzer from which the Alert or
// Heartbeat message originates.  Only one analyzer may be encoded for
// each alert or heartbeat, and that MUST be the analyzer at which the
// alert or heartbeat originated.  Although the IDMEF data model does
// not prevent the use of hierarchical intrusion detection systems
// (where alerts get relayed up the tree), it does not provide any way
// to record the identity of the "relay" analyzers along the path from
// the originating analyzer to the manager that ultimately receives the
// alert. (from RFC 4765)
type Analyzer struct {
	AnalyzerID   string   `xml:"analyzerid,attr"`
	Name         string   `xml:"name,attr,omitempty"`
	Manufacturer string   `xml:"manufacturer,attr,omitempty"`
	Model        string   `xml:"model,attr,omitempty"`
	Version      string   `xml:"version,attr,omitempty"`
	Class        string   `xml:"class,attr,omitempty"`
	OSType       string   `xml:"ostype,attr,omitempty"`
	OSVersion    string   `xml:"osversion,attr,omitempty"`
	Node         *Node    `xml:"idmef:Node"`
	Process      *Process `xml:"idmef:Process"`
}

type Time struct {
	Time     time.Time `xml:",chardata"`
	NtpStamp string    `xml:"ntpstamp,attr"`
}

func NewTime(t time.Time) Time {
	tm := Time{Time: t}
	tm.InflateNtpStamp()
	return tm
}

func (t *Time) InflateNtpStamp() {
	t.NtpStamp = ntp.TimeToNTP(t.Time)
}

type Source struct {
	Ident   string   `xml:"ident,attr,omitempty"`
	Spoofed string   `xml:"spoofed,attr,omitempty"` // Source
	Node    *Node    `xml:"idmef:Node,omitempty"`
	User    *User    `xml:"idmef:User,omitempty"`
	Process *Process `xml:"idmef:Process,omitempty"`
	Service *Service `xml:"idmef:Service,omitempty"`
}

type Target struct {
	Ident   string   `xml:"ident,attr,omitempty"`
	Decoy   string   `xml:"decoy,attr,omitempty"` // Target
	Node    *Node    `xml:"idmef:Node,omitempty"`
	User    *User    `xml:"idmef:User,omitempty"`
	Process *Process `xml:"idmef:Process,omitempty"`
	Service *Service `xml:"idmef:Service,omitempty"`
	File    *File    `xml:"idmef:File,omitempty"`
}

type Node struct {
	Ident    string   `xml:"ident,attr,omitempty"`
	Category string   `xml:"category,attr,omitempty"`
	Address  *Address `xml:"idmef:Address,omitempty"`
	Location string   `xml:"idmef:location,omitempty"`
	Name     string   `xml:"idmef:name,omitempty"`
}

type Address struct {
	Ident    string `xml:"ident,attr,omitempty"`
	Category string `xml:"category,attr,omitempty"`
	Address  string `xml:"idmef:address,omitempty"`
	Netmask  string `xml:"idmef:netmask,omitempty"`
}

type User struct {
	Ident    string   `xml:"ident,attr,omitempty"`
	Category string   `xml:"category,attr,omitempty"`
	UserID   []UserID `xml:"idmef:UserId,omitempty"`
}

type UserID struct {
	Ident  string `xml:"ident,attr,omitempty"`
	Type   string `xml:"type,attr,omitempty"`
	Name   string `xml:"idmef:name,omitempty"`
	Number string `xml:"idmef:number,omitempty"`
}

type Process struct {
	Ident string   `xml:"ident,attr,omitempty"`
	Name  string   `xml:"idmef:name,omitempty"`
	PID   int32    `xml:"idmef:pid,omitempty"`
	Path  string   `xml:"idmef:path,omitempty"`
	Arg   []string `xml:"idmef:arg,omitempty"`
}

type Service struct {
	Ident      string      `xml:"ident,attr,omitempty"`
	Name       string      `xml:"idmef:name,omitempty"`
	Port       int         `xml:"idmef:port,omitempty"`
	Portlist   string      `xml:"idmef:portlist,omitempty"`
	WebService *WebService `xml:"idmef:WebService,omitempty"`
}

type WebService struct {
	URL        string `xml:"idmef:url,omitempty"`
	CGI        string `xml:"idmef:cgi,omitempty"`
	HTTPMethod string `xml:"idmef:http-method,omitempty"`
}

type File struct {
	Category   string       `xml:"category,attr,omitempty"`
	FSType     string       `xml:"fstype,attr,omitempty"`
	Name       string       `xml:"idmef:name,omitempty"`
	Path       string       `xml:"idmef:path,omitempty"`
	FileAccess []FileAccess `xml:"idmef:FileAccess,omitempty"`
	Linkage    *Linkage     `xml:"idmef:Linkage,omitempty"`
}

type FileAccess struct {
	UserID     *UserID      `xml:"idmef:UserId,omitempty"`
	Permission []Permission `xml:"idmef:permission,omitempty"`
}

type Permission struct {
	Perms string `xml:"perms,attr,omitempty"`
}

type Linkage struct {
	Category string `xml:"category,attr,omitempty"`
	Name     string `xml:"idmef:name,omitempty"`
	Path     string `xml:"idmef:path,omitempty"`
}

type Classification struct {
	Ident     string      `xml:"ident,attr,omitempty"`
	Text      string      `xml:"text,attr"`
	Reference []Reference `xml:"idmef:Reference,omitempty"`
}

type Reference struct {
	Origin  string `xml:"origin,attr,omitempty"`
	Meaning string `xml:"meaning,attr,omitempty"`
	Name    string `xml:"idmef:name,omitempty"`
	URL     string `xml:"idmef:url,omitempty"`
}

type Assessment struct {
	Impact     *Impact     `xml:"idmef:Impact,omitempty"`
	Action     []Action    `xml:"idmef:Action,omitempty"`
	Confidence *Confidence `xml:"idmef:Confidence,omitempty"`
}

type Impact struct {
	Severity   string `xml:"severity,attr,omitempty"`
	Completion string `xml:"completion,attr,omitempty"`
	Type       string `xml:"type,attr,omitempty"`
}

type Action struct {
	Action   string `xml:",chardata"`
	Category string `xml:"category,attr,omitempty"`
}

type Confidence struct {
	Rating string `xml:"rating,attr,omitempty"`
}

type CorrelationAlert struct {
	Name       string       `xml:"idmef:name,omitempty"`
	AlertIdent []AlertIdent `xml:"idmef:alertident,omitempty"`
}

type AlertIdent struct {
	AlertIdent string `xml:",chardata"`
	AnalyzerID string `xml:"analyzerid,attr,omitempty"`
}

type AdditionalData struct {
	Type     string    `xml:"type,attr,omitempty"`
	Meaning  string    `xml:"meaning,attr,omitempty"`
	DateTime time.Time `xml:"idmef:date-time,omitempty"`
	Real     *float64  `xml:"idmef:real"`
}
