package unmarshal

import (
	"encoding/xml"
	"os"
	"time"

	"github.com/grokify/go-idmef"
)

type Message struct {
	XMLName    xml.Name   `xml:"http://iana.org/idmef IDMEF-Message"`
	XMLNSIDMEF string     `xml:"xmlns:idmef,attr"`
	Version    string     `xml:"version,attr"`
	Alert      *Alert     `xml:"http://iana.org/idmef Alert"`
	Heartbeat  *Heartbeat `xml:"http://iana.org/idmef Heartbeat"`
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
	if m.Heartbeat != nil {
		cm.Heartbeat = m.Heartbeat.Common()
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
	MessageId        string            `xml:"messageid,attr,omitempty"`
	Analyzer         Analyzer          `xml:"http://iana.org/idmef Analyzer"`
	CreateTime       Time              `xml:"http://iana.org/idmef CreateTime"`
	DetectTime       *Time             `xml:"http://iana.org/idmef DetectTime"`
	AnalyzerTime     *Time             `xml:"http://iana.org/idmef AnalyzerTime"`
	Source           []Source          `xml:"http://iana.org/idmef Source"`
	Target           []Target          `xml:"http://iana.org/idmef Target"`
	Classification   Classification    `xml:"http://iana.org/idmef Classification"`
	Assessment       *Assessment       `xml:"http://iana.org/idmef Assessment"`
	CorrelationAlert *CorrelationAlert `xml:"http://iana.org/idmef CorrelationAlert"`
	AdditionalData   []AdditionalData  `xml:"http://iana.org/idmef AdditionalData"`
}

func (a *Alert) Common() *idmef.Alert {
	cm := &idmef.Alert{
		MessageId:      a.MessageId,
		Analyzer:       a.Analyzer.Common(),
		CreateTime:     a.CreateTime.Common(),
		Source:         []idmef.Source{},
		Target:         []idmef.Target{},
		Classification: a.Classification.Common(),
		AdditionalData: []idmef.AdditionalData{}}
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
	if a.Assessment != nil {
		cm.Assessment = a.Assessment.Common()
	}
	if a.CorrelationAlert != nil {
		cm.CorrelationAlert = a.CorrelationAlert.Common()
	}
	for _, a := range a.AdditionalData {
		cm.AdditionalData = append(cm.AdditionalData, a.Common())
	}
	return cm
}

type Heartbeat struct {
	MessageId      string           `xml:"messageid,attr,omitempty"`
	Analyzer       Analyzer         `xml:"http://iana.org/idmef Analyzer"`
	CreateTime     Time             `xml:"http://iana.org/idmef CreateTime"`
	AdditionalData []AdditionalData `xml:"http://iana.org/idmef AdditionalData"`
}

func (h *Heartbeat) Common() *idmef.Heartbeat {
	cm := &idmef.Heartbeat{
		MessageId:      h.MessageId,
		Analyzer:       h.Analyzer.Common(),
		CreateTime:     h.CreateTime.Common(),
		AdditionalData: []idmef.AdditionalData{}}
	for _, a := range h.AdditionalData {
		cm.AdditionalData = append(cm.AdditionalData, a.Common())
	}
	return cm
}

type Analyzer struct {
	AnalyzerId string `xml:"analyzerid,attr,omitempty"`
	OSType     string `xml:"ostype,attr,omitempty"`
	OSVersion  string `xml:"osversion,attr,omitempty"`
	Node       *Node  `xml:"http://iana.org/idmef Node,omitempty"`
}

func (a *Analyzer) Common() idmef.Analyzer {
	cm := idmef.Analyzer{
		AnalyzerId: a.AnalyzerId,
		OSType:     a.OSType,
		OSVersion:  a.OSVersion}
	if a.Node != nil {
		cm.Node = a.Node.Common()
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
	Node    *Node    `xml:"http://iana.org/idmef Node"`
	User    *User    `xml:"http://iana.org/idmef User"`
	Process *Process `xml:"http://iana.org/idmef Process"`
	Service *Service `xml:"http://iana.org/idmef Service"`
}

func (s *Source) Common() idmef.Source {
	cm := idmef.Source{
		Ident:   s.Ident,
		Spoofed: s.Spoofed}
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

type Target struct {
	Ident   string   `xml:"ident,attr"`
	Decoy   string   `xml:"decoy,attr,omitempty"` // Target
	Node    *Node    `xml:"http://iana.org/idmef Node"`
	User    *User    `xml:"http://iana.org/idmef User"`
	Process *Process `xml:"http://iana.org/idmef Process"`
	Service *Service `xml:"http://iana.org/idmef Service"`
	File    *File    `xml:"http://iana.org/idmef File,omitempty"`
}

func (t *Target) Common() idmef.Target {
	cm := idmef.Target{
		Ident: t.Ident,
		Decoy: t.Decoy}
	if t.Node != nil {
		cm.Node = t.Node.Common()
	}
	if t.User != nil {
		cm.User = t.User.Common()
	}
	if t.Process != nil {
		cm.Process = t.Process.Common()
	}
	if t.Service != nil {
		cm.Service = t.Service.Common()
	}
	if t.File != nil {
		cm.File = t.File.Common()
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
	Ident    string `xml:"ident,attr,omitempty"`
	Category string `xml:"category,attr,omitempty"`
	Address  string `xml:"http://iana.org/idmef address,omitempty"`
	Netmask  string `xml:"http://iana.org/idmef netmask,omitempty"`
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
	Arg  string `xml:"http://iana.org/idmef arg,omitempty"`
}

func (p *Process) Common() *idmef.Process {
	return &idmef.Process{
		Name: p.Name,
		PID:  p.PID,
		Path: p.Path,
		Arg:  p.Arg}
}

type Service struct {
	Ident      string      `xml:"ident,attr,omitempty"`
	Name       string      `xml:"http://iana.org/idmef name,omitempty"`
	Port       int         `xml:"http://iana.org/idmef port,omitempty"`
	Portlist   string      `xml:"http://iana.org/idmef portlist,omitempty"`
	WebService *WebService `xml:"http://iana.org/idmef WebService"`
}

func (s *Service) Common() *idmef.Service {
	cs := &idmef.Service{
		Ident:    s.Ident,
		Name:     s.Name,
		Port:     s.Port,
		Portlist: s.Portlist}
	if s.WebService != nil {
		cs.WebService = s.WebService.Common()
	}
	return cs
}

type WebService struct {
	URL        string `xml:"http://iana.org/idmef url,omitempty"`
	CGI        string `xml:"http://iana.org/idmef cgi,omitempty"`
	HTTPMethod string `xml:"http://iana.org/idmef http-method,omitempty"`
}

func (w WebService) Common() *idmef.WebService {
	return &idmef.WebService{
		URL:        w.URL,
		CGI:        w.CGI,
		HTTPMethod: w.HTTPMethod}
}

type File struct {
	Category   string       `xml:"category,attr,omitempty"`
	FSType     string       `xml:"fstype,attr,omitempty"`
	Name       string       `xml:"http://iana.org/idmef name,omitempty"`
	Path       string       `xml:"http://iana.org/idmef path,omitempty"`
	FileAccess []FileAccess `xml:"http://iana.org/idmef FileAccess,omitempty"`
	Linkage    *Linkage     `xml:"http://iana.org/idmef Linkage,omitempty"`
}

func (f *File) Common() *idmef.File {
	cf := &idmef.File{
		Category:   f.Category,
		FSType:     f.FSType,
		Name:       f.Name,
		Path:       f.Path,
		FileAccess: []idmef.FileAccess{}}
	for _, fa := range f.FileAccess {
		cf.FileAccess = append(cf.FileAccess, fa.Common())
	}
	if f.Linkage != nil {
		cf.Linkage = f.Linkage.Common()
	}
	return cf
}

type FileAccess struct {
	UserId     *UserId      `xml:"http://iana.org/idmef UserId,omitempty"`
	Permission []Permission `xml:"http://iana.org/idmef permission,omitempty"`
}

func (f FileAccess) Common() idmef.FileAccess {
	cf := idmef.FileAccess{
		Permission: []idmef.Permission{}}
	if f.UserId != nil {
		cu := f.UserId.Common()
		cf.UserId = &cu
	}
	for _, p := range f.Permission {
		cf.Permission = append(cf.Permission, p.Common())
	}
	return cf
}

type Permission struct {
	Perms string `xml:"perms,attr,omitempty"`
}

func (p Permission) Common() idmef.Permission {
	return idmef.Permission{
		Perms: p.Perms}
}

type Linkage struct {
	Category string `xml:"category,attr,omitempty"`
	Name     string `xml:"http://iana.org/idmef name,omitempty"`
	Path     string `xml:"http://iana.org/idmef path,omitempty"`
}

func (l *Linkage) Common() *idmef.Linkage {
	return &idmef.Linkage{
		Category: l.Category,
		Name:     l.Name,
		Path:     l.Path}
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

type Assessment struct {
	Impact     *Impact     `xml:"http://iana.org/idmef Impact,omitempty"`
	Action     []Action    `xml:"http://iana.org/idmef Action,omitempty"`
	Confidence *Confidence `xml:"http://iana.org/idmef Confidence,omitempty"`
}

func (a Assessment) Common() *idmef.Assessment {
	ca := &idmef.Assessment{
		Action: []idmef.Action{}}
	if a.Impact != nil {
		ca.Impact = a.Impact.Common()
	}
	for _, action := range a.Action {
		ca.Action = append(ca.Action, action.Common())
	}
	if a.Confidence != nil {
		ca.Confidence = a.Confidence.Common()
	}
	return ca
}

type Impact struct {
	Severity   string `xml:"severity,attr,omitempty"`
	Completion string `xml:"completion,attr,omitempty"`
	Type       string `xml:"type,attr,omitempty"`
}

func (i Impact) Common() *idmef.Impact {
	return &idmef.Impact{
		Severity:   i.Severity,
		Completion: i.Completion,
		Type:       i.Type}
}

type Action struct {
	Action   string `xml:",chardata"`
	Category string `xml:"category,attr,omitempty"`
}

func (a Action) Common() idmef.Action {
	return idmef.Action{
		Action:   a.Action,
		Category: a.Category}
}

type Confidence struct {
	Rating string `xml:"rating,attr,omitempty"`
}

func (c Confidence) Common() *idmef.Confidence {
	return &idmef.Confidence{
		Rating: c.Rating}
}

type CorrelationAlert struct {
	Name       string       `xml:"http://iana.org/idmef name,omitempty"`
	AlertIdent []AlertIdent `xml:"http://iana.org/idmef alertident,omitempty"`
}

func (c CorrelationAlert) Common() *idmef.CorrelationAlert {
	ca := &idmef.CorrelationAlert{
		Name:       c.Name,
		AlertIdent: []idmef.AlertIdent{}}
	for _, alertIdent := range c.AlertIdent {
		ca.AlertIdent = append(ca.AlertIdent, alertIdent.Common())
	}
	return ca
}

type AlertIdent struct {
	AlertIdent string `xml:",chardata"`
	AnalyzerId string `xml:"analyzerid,attr,omitempty"`
}

func (a *AlertIdent) Common() idmef.AlertIdent {
	return idmef.AlertIdent{
		AlertIdent: a.AlertIdent,
		AnalyzerId: a.AnalyzerId}
}

type AdditionalData struct {
	Type     string    `xml:"type,attr,omitempty"`
	Meaning  string    `xml:"meaning,attr,omitempty"`
	DateTime time.Time `xml:"http://iana.org/idmef date-time,omitempty"`
	Real     *float64  `xml:"http://iana.org/idmef real,omitempty"`
}

func (a AdditionalData) Common() idmef.AdditionalData {
	return idmef.AdditionalData{
		Type:     a.Type,
		Meaning:  a.Meaning,
		DateTime: a.DateTime,
		Real:     a.Real}
}
