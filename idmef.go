package idmef

import (
	"encoding/xml"
	"time"

	"github.com/grokify/go-idmef/ntp"
)

const (
	XMLNSIDMEFUrl     = "http://iana.org/idmef"
	XMLNSIDMEFVersion = "1.0"
)

// Message is for authoring. For parsing use
// `github.com/grokify/go-idmef/unmarshal/Message`.
type Message struct {
	XMLName    xml.Name `xml:"idmef:IDMEF-Message"`
	XMLNSIDMEF string   `xml:"xmlns:idmef,attr"`
	Version    string   `xml:"version,attr"`
	Alert      *Alert   `xml:"idmef:Alert"`
}

func (m *Message) Bytes(prefix, indent string) ([]byte, error) {
	if prefix == "" && indent == "" {
		return xml.Marshal(m)
	}
	return xml.MarshalIndent(m, prefix, indent)
}

type Alert struct {
	MessageId      string         `xml:"messageid,attr"`
	Analyzer       Analyzer       `xml:"idmef:Analyzer"`       // Exactly one.
	CreateTime     Time           `xml:"idmef:CreateTime"`     // Exactly one.
	DetectTime     *Time          `xml:"idmef:DetectTime"`     // Zero or one
	AnalyzerTime   *Time          `xml:"idmef:AnalyzerTime"`   // Zero or one.
	Source         []Source       `xml:"idmef:Source"`         // Zero or more.
	Target         []Source       `xml:"idmef:Target"`         // Zero or more.
	Classification Classification `xml:"idmef:Classification"` // Exactly one.
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
	t.NtpStamp = ntp.TimeToNtp(t.Time)
}

type Source struct {
	Ident   string   `xml:"ident,attr,omitempty"`
	Spoofed string   `xml:"spoofed,attr,omitempty"`
	Node    *Node    `xml:"idmef:Node,omitempty"`
	User    *User    `xml:"idmef:User,omitempty"`
	Service *Service `xml:"idmef:Service,omitempty"`
}

type Node struct {
	Ident    string   `xml:"ident,attr,omitempty"`
	Category string   `xml:"category,attr,omitempty"`
	Address  *Address `xml:"idmef:Address,omitempty"`
	Location string   `xml:"idmef:location,omitempty"`
	Name     string   `xml:"idmef:name,omitempty"`
}

type Address struct {
	Ident    string `xml:"ident,attr"`
	Category string `xml:"category,attr"`
	Address  string `xml:"idmef:address"`
	Netmask  string `xml:"idmef:netmask"`
}

type User struct {
	Ident    string  `xml:"ident,attr"`
	Category string  `xml:"category,attr"`
	UserId   *UserId `xml:"idmef:UserId,omitempty"`
}

type UserId struct {
	Ident string `xml:"ident,attr,omitempty"`
	Type  string `xml:"type,attr,omitempty"`
	Name  string `xml:"idmef:name,omitempty"`
}

type Service struct {
	Ident string `xml:"ident,attr,omitempty"`
	Name  string `xml:"idmef:name,omitempty"`
	Port  int    `xml:"idmef:port,omitempty"`
}

type Analyzer struct {
	AnalyzerId string `xml:"analyzerid,attr"`
	Node       *Node  `xml:"idmef:Node"`
}

type Classification struct {
	Text      string      `xml:"text,attr"`
	Reference []Reference `xml:"idmef:Reference,omitempty"`
}

type Reference struct {
	Origin  string `xml:"origin,attr,omitempty"`
	Meaning string `xml:"meaning,attr,omitempty"`
	Name    string `xml:"idmef:name,omitempty"`
	URL     string `xml:"idmef:url,omitempty"`
}
