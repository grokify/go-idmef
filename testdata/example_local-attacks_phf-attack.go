package testdata

import (
	"net/http"
	"time"

	"github.com/grokify/go-idmef"
)

// ExampleLocalAttacksPhfAttack provides the sample file from
// https://datatracker.ietf.org/doc/html/rfc4765#section-7.3.3
func ExampleLocalAttacksPhfAttack() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T08:12:32-01:00")
	if err != nil {
		panic(err)
	}
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFURL,
		Version:    idmef.XMLNSIDMEFVersion,
		Alert: &idmef.Alert{
			MessageID: "abc123456789",
			Analyzer: idmef.Analyzer{
				AnalyzerID: "bc-sensor01",
				Node: &idmef.Node{
					Category: idmef.ServiceDNS,
					Name:     "sensor.example.com",
				},
			},
			CreateTime: idmef.NewTime(dt),
			Source: []idmef.Source{
				{
					Ident: "abc123",
					Node: &idmef.Node{
						Ident: "abc123-001",
						Address: &idmef.Address{
							Ident:    "abc123-002",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.200",
						},
					},
					Service: &idmef.Service{
						Ident: "abc123-003",
						Port:  21534,
					},
				},
			},
			Target: []idmef.Target{
				{
					Ident: "xyz789",
					Node: &idmef.Node{
						Ident:    "xyz789-001",
						Category: idmef.ServiceDNS,
						Name:     "www.example.com",
						Address: &idmef.Address{
							Ident:    "xyz789-002",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.100",
						},
					},
					Service: &idmef.Service{
						Port: 8080,
						WebService: &idmef.WebService{
							URL:        "http://www.example.com/cgi-bin/phf?/etc/group",
							CGI:        "/cgi-bin/phf",
							HTTPMethod: http.MethodGet,
						},
					},
				},
			},
			Classification: idmef.Classification{
				Text: "phf attack",
				Reference: []idmef.Reference{
					{
						Origin: "bugtraqid",
						Name:   "629",
						URL:    "http://www.securityfocus.com/bid/629",
					},
				},
			},
		},
	}
	return msg
}

func ExampleLocalAttacksPhfAttackString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
	<idmef:IDMEF-Message version="1.0"
		xmlns:idmef="http://iana.org/idmef">
		<idmef:Alert messageid="abc123456789">
			<idmef:Analyzer analyzerid="bc-sensor01">
				<idmef:Node category="dns">
					<idmef:name>sensor.example.com</idmef:name>
				</idmef:Node>
			</idmef:Analyzer>
			<idmef:CreateTime ntpstamp="0xbc71e980.0x00000000">2000-03-09T08:12:32-01:00</idmef:CreateTime>
			<idmef:Source ident="abc123">
				<idmef:Node ident="abc123-001">
					<idmef:Address ident="abc123-002"
							  category="ipv4-addr">
						<idmef:address>192.0.2.200</idmef:address>
					</idmef:Address>
				</idmef:Node>
				<idmef:Service ident="abc123-003">
					<idmef:port>21534</idmef:port>
				</idmef:Service>
			</idmef:Source>
			<idmef:Target ident="xyz789">
				<idmef:Node ident="xyz789-001" category="dns">
					<idmef:name>www.example.com</idmef:name>
					<idmef:Address ident="xyz789-002"
							  category="ipv4-addr">
						<idmef:address>192.0.2.100</idmef:address>
					</idmef:Address>
				</idmef:Node>
				<idmef:Service>
					<idmef:port>8080</idmef:port>
					<idmef:WebService>
						<idmef:url>http://www.example.com/cgi-bin/phf?/etc/group</idmef:url>
						<idmef:cgi>/cgi-bin/phf</idmef:cgi>
						<idmef:http-method>GET</idmef:http-method>
					</idmef:WebService>
				</idmef:Service>
			</idmef:Target>
			<idmef:Classification text="phf attack">
				<idmef:Reference origin="bugtraqid">
					<idmef:name>629</idmef:name>
					<idmef:url>http://www.securityfocus.com/bid/629</idmef:url>
				</idmef:Reference>
			</idmef:Classification>
		</idmef:Alert>
	</idmef:IDMEF-Message>`
}
