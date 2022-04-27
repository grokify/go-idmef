package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// ExamplePortScanningDisallowedService provides the sample file from
// https://datatracker.ietf.org/doc/html/rfc4765#section-7.2.1
func ExamplePortScanningDisallowedService() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T18:47:25+02:00")
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
					Ident: "a123",
					Node: &idmef.Node{
						Ident: "a123-01",
						Address: &idmef.Address{
							Ident:    "a123-02",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.200",
						},
					},
					User: &idmef.User{
						Ident:    "q987-03",
						Category: idmef.CategoryOSDevice,
						UserID: []idmef.UserID{{
							Ident: "q987-04",
							Type:  "target-user",
							Name:  "badguy",
						}},
					},
					Service: &idmef.Service{
						Ident: "a123-03",
						Port:  31532,
					},
				},
			},
			Target: []idmef.Target{
				{
					Ident: "z456",
					Node: &idmef.Node{
						Ident:    "z456-01",
						Category: idmef.ServiceNIS,
						Name:     "myhost",
						Address: &idmef.Address{
							Ident:    "z456-02",
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.50",
						},
					},
					Service: &idmef.Service{
						Ident: "z456-03",
						Name:  idmef.ServiceFinger,
						Port:  79,
					},
				},
			},
			Classification: idmef.Classification{
				Text: "Portscan",
				Reference: []idmef.Reference{
					{
						Origin: idmef.OriginVendorSpecific,
						Name:   idmef.ServiceFinger,
						URL:    "http://www.vendor.com/finger",
					},
					{
						Origin:  idmef.OriginVendorSpecific,
						Meaning: "general documentation",
						Name:    "Distributed attack",
						URL:     "http://www.vendor.com/distributed",
					},
				},
			},
		},
	}
	return msg
}

func ExamplePortScanningDisallowedServiceString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<idmef:IDMEF-Message version="1.0"
	xmlns:idmef="http://iana.org/idmef">
	<idmef:Alert messageid="abc123456789">
		<idmef:Analyzer analyzerid="bc-sensor01">
			<idmef:Node category="dns">
				<idmef:name>sensor.example.com</idmef:name>
			</idmef:Node>
		</idmef:Analyzer>
		<idmef:CreateTime ntpstamp="0xbc72541d.0x00000000">
         2000-03-09T18:47:25+02:00
       </idmef:CreateTime>
		<idmef:Source ident="a123">
			<idmef:Node ident="a123-01">
				<idmef:Address ident="a123-02" category="ipv4-addr">
					<idmef:address>192.0.2.200</idmef:address>
				</idmef:Address>
			</idmef:Node>
			<idmef:User ident="q987-03" category="os-device">
				<idmef:UserId ident="q987-04" type="target-user">
					<idmef:name>badguy</idmef:name>
				</idmef:UserId>
			</idmef:User>
			<idmef:Service ident="a123-03">
				<idmef:port>31532</idmef:port>
			</idmef:Service>
		</idmef:Source>
		<idmef:Target ident="z456">
			<idmef:Node ident="z456-01" category="nis">
				<idmef:name>myhost</idmef:name>
				<idmef:Address ident="z456-02" category="ipv4-addr">
					<idmef:address>192.0.2.50</idmef:address>
				</idmef:Address>
			</idmef:Node>
			<idmef:Service ident="z456-03">
				<idmef:name>finger</idmef:name>
				<idmef:port>79</idmef:port>
			</idmef:Service>
		</idmef:Target>
		<idmef:Classification text="Portscan">
			<idmef:Reference origin="vendor-specific">
				<idmef:name>finger</idmef:name>
				<idmef:url>http://www.vendor.com/finger</idmef:url>
			</idmef:Reference>
			<idmef:Reference origin="vendor-specific"
                          meaning="general documentation">
				<idmef:name>Distributed attack</idmef:name>
				<idmef:url>http://www.vendor.com/distributed</idmef:url>
			</idmef:Reference>
		</idmef:Classification>
	</idmef:Alert>
</idmef:IDMEF-Message>`
}
