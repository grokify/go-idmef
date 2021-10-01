package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// ExamplePortScanningSimple provides the sample file from
// https://datatracker.ietf.org/doc/html/rfc4765#section-7.2.2
func ExamplePortScanningSimple() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T15:31:00-08:00")
	if err != nil {
		panic(err)
	}
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFUrl,
		Version:    idmef.XMLNSIDMEFVersion,
		Alert: &idmef.Alert{
			MessageId: "abc123456789",
			Analyzer: idmef.Analyzer{
				AnalyzerId: "hq-dmz-analyzer62",
				Node: &idmef.Node{
					Category: idmef.ServiceDNS,
					Location: "Headquarters Web Server",
					Name:     "analyzer62.example.com",
				},
			},
			CreateTime: idmef.NewTime(dt),
			Source: []idmef.Source{
				{
					Ident: "abc01",
					Node: &idmef.Node{
						Ident: "abc01-01",
						Address: &idmef.Address{
							Ident:    "abc01-02",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.200",
						},
					},
				},
			},
			Target: []idmef.Target{
				{
					Ident: "def01",
					Node: &idmef.Node{
						Ident:    "def01-01",
						Category: idmef.ServiceDNS,
						Name:     "www.example.com",
						Address: &idmef.Address{
							Ident:    "def01-02",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.50",
						},
					},
					Service: &idmef.Service{
						Ident:    "def01-03",
						Portlist: "5-25,37,42,43,53,69-119,123-514",
					},
				},
			},
			Classification: idmef.Classification{
				Text: "simple portscan",
				Reference: []idmef.Reference{
					{
						Origin: idmef.OriginVendorSpecific,
						Name:   "portscan",
						URL:    "http://www.vendor.com/portscan",
					},
				},
			},
		},
	}
	return msg
}

func ExamplePortScanningSimpleString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
	<idmef:IDMEF-Message version="1.0"
		xmlns:idmef="http://iana.org/idmef">
		<idmef:Alert messageid="abc123456789">
			<idmef:Analyzer analyzerid="hq-dmz-analyzer62">
				<idmef:Node category="dns">
					<idmef:location>Headquarters Web Server</idmef:location>
					<idmef:name>analyzer62.example.com</idmef:name>
				</idmef:Node>
			</idmef:Analyzer>
			<idmef:CreateTime ntpstamp="0xbc72b2b4.0x00000000">2000-03-09T15:31:00-08:00</idmef:CreateTime>
			<idmef:Source ident="abc01">
				<idmef:Node ident="abc01-01">
					<idmef:Address ident="abc01-02" category="ipv4-addr">
						<idmef:address>192.0.2.200</idmef:address>
					</idmef:Address>
				</idmef:Node>
			</idmef:Source>
			<idmef:Target ident="def01">
				<idmef:Node ident="def01-01" category="dns">
					<idmef:name>www.example.com</idmef:name>
					<idmef:Address ident="def01-02" category="ipv4-addr">
						<idmef:address>192.0.2.50</idmef:address>
					</idmef:Address>
				</idmef:Node>
				<idmef:Service ident="def01-03">
					<idmef:portlist>5-25,37,42,43,53,69-119,123-514
			   </idmef:portlist>
				</idmef:Service>
			</idmef:Target>
			<idmef:Classification text="simple portscan">
				<idmef:Reference origin="vendor-specific">
					<idmef:name>portscan</idmef:name>
					<idmef:url>http://www.vendor.com/portscan</idmef:url>
				</idmef:Reference>
			</idmef:Classification>
		</idmef:Alert>
	</idmef:IDMEF-Message>`
}
