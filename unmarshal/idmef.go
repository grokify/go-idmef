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

func ReadFile(filename string) (*idmef.Message, error) {
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
	MessageId      string         `xml:"messageid,attr"`
	Analyzer       Analyzer       `xml:"http://iana.org/idmef Analyzer"`
	CreateTime     Time           `xml:"http://iana.org/idmef CreateTime"`
	DetectTime     *Time          `xml:"http://iana.org/idmef DetectTime"`
	AnalyzerTime   *Time          `xml:"http://iana.org/idmef AnalyzerTime"`
	Source         []Source       `xml:"http://iana.org/idmef Source"`
	Target         []Source       `xml:"http://iana.org/idmef Target"`
	Classification Classification `xml:"http://iana.org/idmef Classification"`
}

func (a *Alert) Common() *idmef.Alert {
	cm := &idmef.Alert{
		MessageId:      a.MessageId,
		Analyzer:       a.Analyzer.Common(),
		CreateTime:     a.CreateTime.Common(),
		Source:         []idmef.Source{},
		Target:         []idmef.Source{},
		Classification: a.Classification.Common()}
	if a.DetectTime != nil {
		dt := a.DetectTime.Common()
		cm.DetectTime = &dt
	}
	if a.AnalyzerTime != nil {
		dt := a.AnalyzerTime.Common()
		cm.AnalyzerTime = &dt
	}
	for _, s := range a.Source {
		cm.Source = append(cm.Source, s.Common())
	}
	for _, t := range a.Target {
		cm.Target = append(cm.Target, t.Common())
	}
	return cm
}

type Time struct {
	Time     time.Time `xml:",chardata"`
	NtpStamp string    `xml:"ntpstamp,attr"`
}

func (t *Time) Common() idmef.Time {
	return idmef.Time{
		Time:     t.Time,
		NtpStamp: t.NtpStamp}
}

type Source struct {
	Ident   string   `xml:"ident,attr"`
	Spoofed string   `xml:"spoofed,attr,omitempty"` // Source
	Decoy   string   `xml:"decoy,attr,omitempty"`   // Target
	Node    *Node    `xml:"http://iana.org/idmef Node"`
	User    *User    `xml:"http://iana.org/idmef User"`
	Process *Process `xml:"http://iana.org/idmef Process"`
	Service *Service `xml:"http://iana.org/idmef Service"`
}

func (s *Source) Common() idmef.Source {
	cm := idmef.Source{
		Ident:   s.Ident,
		Spoofed: s.Spoofed,
		Decoy:   s.Decoy}
	if s.Node != nil {
		cm.Node = s.Node.Common()
	}
	if s.User != nil {
		cm.User = s.User.Common()
	}
	if s.Process != nil {
		cm.Process = s.Process.Common()
	}
	if s.Service != nil {
		cm.Service = s.Service.Common()
	}
	return cm
}

type Node struct {
	Ident    string   `xml:"ident,attr,omitempty"`
	Category string   `xml:"category,attr,omitempty"`
	Name     string   `xml:"http://iana.org/idmef name,omitempty"`
	Address  *Address `xml:"http://iana.org/idmef Address,omitempty"`
	Location string   `xml:"http://iana.org/idmef location,omitempty"`
}

func (n *Node) Common() *idmef.Node {
	cm := &idmef.Node{
		Ident:    n.Ident,
		Category: n.Category,
		Location: n.Location,
		Name:     n.Name}
	if n.Address != nil {
		cm.Address = n.Address.Common()
	}
	return cm
}

type Address struct {
	Ident    string `xml:"ident,attr"`
	Category string `xml:"category,attr"`
	Address  string `xml:"http://iana.org/idmef address"`
	Netmask  string `xml:"http://iana.org/idmef netmask"`
}

func (a *Address) Common() *idmef.Address {
	return &idmef.Address{
		Ident:    a.Ident,
		Category: a.Category,
		Address:  a.Address,
		Netmask:  a.Netmask}
}

type User struct {
	Ident    string   `xml:"ident,attr,omitempty"`
	Category string   `xml:"category,attr,omitempty"`
	UserId   []UserId `xml:"http://iana.org/idmef UserId,omitempty"`
}

func (u *User) Common() *idmef.User {
	uc := &idmef.User{
		Ident:    u.Ident,
		Category: u.Category,
		UserId:   []idmef.UserId{}}
	for _, usrId := range u.UserId {
		uc.UserId = append(uc.UserId, usrId.Common())
	}
	return uc
}

type UserId struct {
	Ident  string `xml:"ident,attr,omitempty"`
	Type   string `xml:"type,attr,omitempty"`
	Name   string `xml:"http://iana.org/idmef name,omitempty"`
	Number string `xml:"http://iana.org/idmef number,omitempty"`
}

func (u *UserId) Common() idmef.UserId {
	return idmef.UserId{
		Ident:  u.Ident,
		Type:   u.Type,
		Name:   u.Name,
		Number: u.Number}
}

type Process struct {
	Name string `xml:"http://iana.org/idmef name,omitempty"`
	PID  int    `xml:"http://iana.org/idmef pid,omitempty"`
	Path string `xml:"http://iana.org/idmef path,omitempty"`
	Arg  int    `xml:"http://iana.org/idmef arg,omitempty"`
}

func (p *Process) Common() *idmef.Process {
	return &idmef.Process{
		Name: p.Name,
		PID:  p.PID,
		Path: p.Path,
		Arg:  p.Arg}
}

type Service struct {
	Ident string `xml:"ident,attr,omitempty"`
	Name  string `xml:"http://iana.org/idmef name,omitempty"`
	Port  int    `xml:"http://iana.org/idmef port,omitempty"`
}

func (s *Service) Common() *idmef.Service {
	return &idmef.Service{
		Ident: s.Ident,
		Name:  s.Name,
		Port:  s.Port}
}

type Analyzer struct {
	AnalyzerId string `xml:"analyzerid,attr,omitempty"`
	Node       *Node  `xml:"http://iana.org/idmef Node,omitempty"`
}

func (a *Analyzer) Common() idmef.Analyzer {
	cm := idmef.Analyzer{
		AnalyzerId: a.AnalyzerId}
	if a.Node != nil {
		cm.Node = a.Node.Common()
	}
	return cm
}

type Classification struct {
	Text      string      `xml:"text,attr"`
	Reference []Reference `xml:"http://iana.org/idmef Reference"`
}

func (cl *Classification) Common() idmef.Classification {
	cm := idmef.Classification{
		Text:      cl.Text,
		Reference: []idmef.Reference{}}
	for _, ref := range cl.Reference {
		cm.Reference = append(cm.Reference, ref.Common())
	}
	return cm
}

type Reference struct {
	Origin  string `xml:"origin,attr,omitempty"`
	Meaning string `xml:"meaning,attr,omitempty"`
	Name    string `xml:"http://iana.org/idmef name,omitempty"`
	URL     string `xml:"http://iana.org/idmef url,omitempty"`
}

func (ref *Reference) Common() idmef.Reference {
	return idmef.Reference{
		Origin:  ref.Origin,
		Meaning: ref.Meaning,
		Name:    ref.Name,
		URL:     ref.URL}
}
