package testdata

import (
	"time"

	idmef "github.com/grokify/go-idmef"
)

// ExampleAlertCorrelatedAlerts provides the sample file from
// https://datatracker.ietf.org/doc/html/rfc4765#section-7.5
func ExampleAlertCorrelatedAlerts() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T15:31:07Z")
	if err != nil {
		panic(err)
	}
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFURL,
		Version:    idmef.XMLNSIDMEFVersion,
		Alert: &idmef.Alert{
			MessageID: "abc123456789",
			Analyzer: idmef.Analyzer{
				AnalyzerID: "bc-corr-01",
				Node: &idmef.Node{
					Category: idmef.ServiceDNS,
					Name:     "correlator01.example.com",
				},
			},
			CreateTime: idmef.NewTime(dt),
			Source: []idmef.Source{
				{
					Ident: "a1",
					Node: &idmef.Node{
						Ident: "a1-1",
						Address: &idmef.Address{
							Ident:    "a1-2",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.200",
						},
					},
				},
			},
			Target: []idmef.Target{
				{
					Ident: "a2",
					Node: &idmef.Node{
						Ident:    "a2-1",
						Category: idmef.ServiceDNS,
						Name:     "www.example.com",
						Address: &idmef.Address{
							Ident:    "a2-2",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.50",
						},
					},
					Service: &idmef.Service{
						Ident:    "a2-3",
						Portlist: "5-25,37,42,43,53,69-119,123-514",
					},
				},
			},
			Classification: idmef.Classification{
				Text: "Portscan",
				Reference: []idmef.Reference{{
					Origin: idmef.OriginVendorSpecific,
					Name:   "portscan",
					URL:    "http://www.vendor.com/portscan",
				}},
			},
			CorrelationAlert: &idmef.CorrelationAlert{
				Name: "multiple ports in short time",
				AlertIdent: []idmef.AlertIdent{
					{AlertIdent: "123456781"},
					{AlertIdent: "123456782"},
					{AlertIdent: "123456783"},
					{AlertIdent: "123456784"},
					{AlertIdent: "123456785"},
					{AlertIdent: "123456786"},
					{AlertIdent: "987654321", AnalyzerID: "a1b2c3d4"},
					{AlertIdent: "987654322", AnalyzerID: "a1b2c3d4"},
				},
			},
		},
	}
	return msg
}

func ExampleAlertCorrelatedAlertsString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
	<idmef:IDMEF-Message version="1.0"
		xmlns:idmef="http://iana.org/idmef">
		<idmef:Alert messageid="abc123456789">
			<idmef:Analyzer analyzerid="bc-corr-01">
				<idmef:Node category="dns">
					<idmef:name>correlator01.example.com</idmef:name>
				</idmef:Node>
			</idmef:Analyzer>
			<idmef:CreateTime ntpstamp="0xbc72423b.0x00000000">2000-03-09T15:31:07Z</idmef:CreateTime>
			<idmef:Source ident="a1">
				<idmef:Node ident="a1-1">
					<idmef:Address ident="a1-2" category="ipv4-addr">
						<idmef:address>192.0.2.200</idmef:address>
					</idmef:Address>
				</idmef:Node>
			</idmef:Source>
			<idmef:Target ident="a2">
				<idmef:Node ident="a2-1" category="dns">
					<idmef:name>www.example.com</idmef:name>
					<idmef:Address ident="a2-2" category="ipv4-addr">
						<idmef:address>192.0.2.50</idmef:address>
					</idmef:Address>
				</idmef:Node>
				<idmef:Service ident="a2-3">
					<idmef:portlist>5-25,37,42,43,53,69-119,123-514</idmef:portlist>
				</idmef:Service>
			</idmef:Target>
			<idmef:Classification text="Portscan">
				<idmef:Reference origin="vendor-specific">
					<idmef:name>portscan</idmef:name>
					<idmef:url>http://www.vendor.com/portscan</idmef:url>
				</idmef:Reference>
			</idmef:Classification>
			<idmef:CorrelationAlert>
				<idmef:name>multiple ports in short time</idmef:name>
				<idmef:alertident>123456781</idmef:alertident>
				<idmef:alertident>123456782</idmef:alertident>
				<idmef:alertident>123456783</idmef:alertident>
				<idmef:alertident>123456784</idmef:alertident>
				<idmef:alertident>123456785</idmef:alertident>
				<idmef:alertident>123456786</idmef:alertident>
				<idmef:alertident analyzerid="a1b2c3d4">987654321</idmef:alertident>
				<idmef:alertident analyzerid="a1b2c3d4">987654322</idmef:alertident>
			</idmef:CorrelationAlert>
		</idmef:Alert>
	</idmef:IDMEF-Message>`
}
