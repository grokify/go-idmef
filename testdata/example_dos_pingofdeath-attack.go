package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// ExampleAlertPingOfDeathAttack provides the sample file from
// https://datatracker.ietf.org/doc/html/rfc4765#section-7.1.2
func ExampleAlertPingOfDeathAttack() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T10:01:25.93464Z")
	if err != nil {
		panic(err)
	}
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFUrl,
		Version:    idmef.XMLNSIDMEFVersion,
		Alert: &idmef.Alert{
			MessageId: "abc123456789",
			Analyzer: idmef.Analyzer{
				AnalyzerId: "bc-sensor01",
				Node: &idmef.Node{
					Category: idmef.ServiceDNS,
					Name:     "sensor.example.com",
				},
			},
			CreateTime: idmef.NewTime(dt),
			Source: []idmef.Source{
				{
					Ident:   "a1a2",
					Spoofed: "yes",
					Node: &idmef.Node{
						Ident: "a1a2-1",
						Address: &idmef.Address{
							Ident:    "a1a2-2",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.200",
						},
					},
				},
			},
			Target: []idmef.Target{
				{
					Ident: "b3b4",
					Node: &idmef.Node{
						Address: &idmef.Address{
							Ident:    "b3b4-1",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.50",
						},
					},
				},
				{
					Ident: "c5c6",
					Node: &idmef.Node{
						Ident:    "c5c6-1",
						Category: idmef.ServiceNISPlus,
						Name:     "lollipop",
					},
				},
				{
					Ident: "d7d8",
					Node: &idmef.Node{
						Ident:    "d7d8-1",
						Location: "Cabinet B10",
						Name:     "Cisco.router.b10",
					},
				},
			},
			Classification: idmef.Classification{
				Text: "Ping-of-death detected",
				Reference: []idmef.Reference{{
					Origin: "cve",
					Name:   "CVE-1999-128",
					URL:    "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-128",
				}},
			},
		},
	}
	return msg
}

func ExampleAlertPingOfDeathAttackString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
	<idmef:IDMEF-Message version="1.0"
		xmlns:idmef="http://iana.org/idmef">
		<idmef:Alert messageid="abc123456789">
			<idmef:Analyzer analyzerid="bc-sensor01">
				<idmef:Node category="dns">
					<idmef:name>sensor.example.com</idmef:name>
				</idmef:Node>
			</idmef:Analyzer>
			<idmef:CreateTime ntpstamp="0xbc71f4f5.0xef449129">2000-03-09T10:01:25.93464Z</idmef:CreateTime>
			<idmef:Source ident="a1a2" spoofed="yes">
				<idmef:Node ident="a1a2-1">
					<idmef:Address ident="a1a2-2" category="ipv4-addr">
						<idmef:address>192.0.2.200</idmef:address>
					</idmef:Address>
				</idmef:Node>
			</idmef:Source>
			<idmef:Target ident="b3b4">
				<idmef:Node>
					<idmef:Address ident="b3b4-1" category="ipv4-addr">
						<idmef:address>192.0.2.50</idmef:address>
					</idmef:Address>
				</idmef:Node>
			</idmef:Target>
			<idmef:Target ident="c5c6">
				<idmef:Node ident="c5c6-1" category="nisplus">
					<idmef:name>lollipop</idmef:name>
				</idmef:Node>
			</idmef:Target>
			<idmef:Target ident="d7d8">
				<idmef:Node ident="d7d8-1">
					<idmef:location>Cabinet B10</idmef:location>
					<idmef:name>Cisco.router.b10</idmef:name>
				</idmef:Node>
			</idmef:Target>
			<idmef:Classification text="Ping-of-death detected">
				<idmef:Reference origin="cve">
					<idmef:name>CVE-1999-128</idmef:name>
					<idmef:url>http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-128</idmef:url>
				</idmef:Reference>
			</idmef:Classification>
		</idmef:Alert>
	</idmef:IDMEF-Message>`
}
