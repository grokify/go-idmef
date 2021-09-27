package unmarshal

import (
	"encoding/xml"
	"os"
	"time"

	"github.com/grokify/go-idmef"
)

type Message struct {
	XMLName    xml.Name `xml:"http://iana.org/idmef IDMEF-Message"`
	XMLNSIDMEF string   `xml:"xmlns:idmef,attr"`
	Version    string   `xml:"version,attr"`
	Alert      *Alert   `xml:"http://iana.org/idmef Alert"`
}

func ParseFile(filename string) (*idmef.Message, error) {
	fdata, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	unMsg := &Message{}
	err = xml.Unmarshal(fdata, unMsg)
	if err != nil {
		return nil, err
	}
	return unMsg.Common(), nil
}

func (m *Message) Common() *idmef.Message {
	cm := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFUrl,
		Version:    m.Version}
	if m.Alert != nil {
		cm.Alert = m.Alert.Common()
	}
	return cm
}

func (m *Message) Bytes(prefix, indent string) ([]byte, error) {
	if prefix == "" && indent == "" {
		return xml.Marshal(m)
	}
	return xml.MarshalIndent(m, prefix, indent)
}

type Alert struct {
	MessageId      string          `xml:"messageid,attr"`
	Analyzer       *Analyzer       `xml:"http://iana.org/idmef Analyzer"`
	CreateTime     *Time           `xml:"http://iana.org/idmef CreateTime"`
	Source         *Source         `xml:"http://iana.org/idmef Source"`
	Target         []*Source       `xml:"http://iana.org/idmef Target"`
	Classification *Classification `xml:"http://iana.org/idmef Classification"`
}

func (a *Alert) Common() *idmef.Alert {
	cm := &idmef.Alert{
		MessageId: a.MessageId,
		Target:    []*idmef.Source{}}
	if a.Analyzer != nil {
		cm.Analyzer = a.Analyzer.Common()
	}
	if a.CreateTime != nil {
		cm.CreateTime = a.CreateTime.Common()
	}
	if a.Source != nil {
		cm.Source = a.Source.Common()
	}
	if len(a.Target) > 0 {
		for _, t := range a.Target {
			cm.Target = append(cm.Target, t.Common())
		}
	}
	if a.Classification != nil {
		cm.Classification = a.Classification.Common()
	}
	return cm
}

type Time struct {
	Time     time.Time `xml:",chardata"`
	NtpStamp string    `xml:"ntpstamp,attr"`
}

func (t *Time) Common() *idmef.Time {
	return &idmef.Time{
		Time:     t.Time,
		NtpStamp: t.NtpStamp}
}

type Source struct {
	Indent  string `xml:"ident,attr"`
	Spoofed string `xml:"spoofed,attr,omitempty"`
	Node    *Node  `xml:"http://iana.org/idmef Node"`
}

func (s *Source) Common() *idmef.Source {
	cm := &idmef.Source{
		Indent:  s.Indent,
		Spoofed: s.Spoofed}
	if s.Node != nil {
		cm.Node = s.Node.Common()
	}
	return cm
}

type Node struct {
	Indent   string   `xml:"ident,attr,omitempty"`
	Category string   `xml:"category,attr,omitempty"`
	Address  *Address `xml:"http://iana.org/idmef Address,omitempty"`
	Location string   `xml:"http://iana.org/idmef location,omitempty"`
	Name     string   `xml:"http://iana.org/idmef name,omitempty"`
}

func (n *Node) Common() *idmef.Node {
	cm := &idmef.Node{
		Indent:   n.Indent,
		Category: n.Category,
		Location: n.Location,
		Name:     n.Name}
	if n.Address != nil {
		cm.Address = n.Address.Common()
	}
	return cm
}

type Address struct {
	Address  string `xml:"http://iana.org/idmef address"`
	Indent   string `xml:"ident,attr"`
	Category string `xml:"category,attr"`
}

func (a *Address) Common() *idmef.Address {
	return &idmef.Address{
		Address:  a.Address,
		Indent:   a.Indent,
		Category: a.Category}
}

type Analyzer struct {
	AnalyzerId string `xml:"analyzerid,attr"`
	Node       *Node  `xml:"http://iana.org/idmef Node"`
}

func (a *Analyzer) Common() *idmef.Analyzer {
	cm := &idmef.Analyzer{
		AnalyzerId: a.AnalyzerId}
	if a.Node != nil {
		cm.Node = a.Node.Common()
	}
	return cm
}

type Classification struct {
	Text      string     `xml:"text,attr"`
	Reference *Reference `xml:"http://iana.org/idmef Reference"`
}

func (cl *Classification) Common() *idmef.Classification {
	cm := &idmef.Classification{
		Text: cl.Text}
	if cl.Reference != nil {
		cm.Reference = cl.Reference.Common()
	}
	return cm
}

type Reference struct {
	Origin string `xml:"origin,attr"`
	Name   string `xml:"http://iana.org/idmef name"`
	URL    string `xml:"http://iana.org/idmef url"`
}

func (ref *Reference) Common() *idmef.Reference {
	return &idmef.Reference{
		Origin: ref.Origin,
		Name:   ref.Name,
		URL:    ref.URL}
}
