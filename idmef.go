package idmef

import (
	"encoding/xml"
	"time"
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
	MessageId      string          `xml:"messageid,attr"`
	Analyzer       *Analyzer       `xml:"idmef:Analyzer"`
	CreateTime     *Time           `xml:"idmef:CreateTime"`
	Source         *Source         `xml:"idmef:Source"`
	Target         []*Source       `xml:"idmef:Target"`
	Classification *Classification `xml:"idmef:Classification"`
}

type Time struct {
	Time     time.Time `xml:",chardata"`
	NtpStamp string    `xml:"ntpstamp,attr"`
}

type Source struct {
	Indent  string `xml:"ident,attr,omitempty"`
	Spoofed string `xml:"spoofed,attr,omitempty"`
	Node    *Node  `xml:"idmef:Node"`
}

type Node struct {
	Indent   string   `xml:"ident,attr,omitempty"`
	Category string   `xml:"category,attr,omitempty"`
	Address  *Address `xml:"idmef:Address,omitempty"`
	Location string   `xml:"idmef:location,omitempty"`
	Name     string   `xml:"idmef:name,omitempty"`
}

type Address struct {
	Address  string `xml:"idmef:address"`
	Indent   string `xml:"ident,attr"`
	Category string `xml:"category,attr"`
}

type Analyzer struct {
	AnalyzerId string `xml:"analyzerid,attr"`
	Node       *Node  `xml:"idmef:Node"`
}

type Classification struct {
	Text      string     `xml:"text,attr"`
	Reference *Reference `xml:"idmef:Reference"`
}

type Reference struct {
	Origin string `xml:"origin,attr"`
	Name   string `xml:"idmef:name"`
	URL    string `xml:"idmef:url"`
}
