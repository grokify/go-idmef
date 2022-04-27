package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// ExampleAlertTeardropAttack provides the sample file from
// https://datatracker.ietf.org/doc/html/draft-ietf-idwg-idmef-xml#section-7.1.1
func ExampleAlertTeardropAttack() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T10:01:25.93464-05:00")
	if err != nil {
		panic(err)
	}
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFURL,
		Version:    idmef.XMLNSIDMEFVersion,
		Alert: &idmef.Alert{
			MessageID: "abc123456789",
			Analyzer: idmef.Analyzer{
				AnalyzerID: "hq-dmz-analyzer01",
				Node: &idmef.Node{
					Category: idmef.ServiceDNS,
					Location: "Headquarters DMZ Network",
					Name:     "analyzer01.example.com",
				},
			},
			CreateTime: idmef.NewTime(dt),
			Source: []idmef.Source{
				{
					Ident: "a1b2c3d4",
					Node: &idmef.Node{
						Ident:    "a1b2c3d4-001",
						Category: idmef.ServiceDNS,
						Name:     "badguy.example.net",
						Address: &idmef.Address{
							Ident:    "a1b2c3d4-002",
							Category: idmef.IPV4NetMask,
							Address:  "192.0.2.50",
							Netmask:  "255.255.255.255",
						},
					},
				},
			},
			Target: []idmef.Target{
				{
					Ident: "d1c2b3a4",
					Node: &idmef.Node{
						Ident:    "d1c2b3a4-001",
						Category: idmef.ServiceDNS,
						Address: &idmef.Address{
							Category: idmef.IPV4AddrHex,
							Address:  "0xde796f70",
						},
					},
				},
			},
			Classification: idmef.Classification{
				Text: "Teardrop detected",
				Reference: []idmef.Reference{{
					Origin: "bugtraqid",
					Name:   "124",
					URL:    "http://www.securityfocus.com/bid/124",
				}},
			},
		},
	}
	return msg
}

func ExampleAlertTeardropAttackString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<idmef:IDMEF-Message
	xmlns:idmef="http://iana.org/idmef"
                        version="1.0">
	<idmef:Alert messageid="abc123456789">
		<idmef:Analyzer analyzerid="hq-dmz-analyzer01">
			<idmef:Node category="dns">
				<idmef:location>Headquarters DMZ Network</idmef:location>
				<idmef:name>analyzer01.example.com</idmef:name>
			</idmef:Node>
		</idmef:Analyzer>
		<idmef:CreateTime ntpstamp="0xbc723b45.0xef449129">2000-03-09T10:01:25.93464-05:00</idmef:CreateTime>
		<idmef:Source ident="a1b2c3d4">
			<idmef:Node ident="a1b2c3d4-001" category="dns">
				<idmef:name>badguy.example.net</idmef:name>
				<idmef:Address ident="a1b2c3d4-002"
                          category="ipv4-net-mask">
					<idmef:address>192.0.2.50</idmef:address>
					<idmef:netmask>255.255.255.255</idmef:netmask>
				</idmef:Address>
			</idmef:Node>
		</idmef:Source>
		<idmef:Target ident="d1c2b3a4">
			<idmef:Node ident="d1c2b3a4-001" category="dns">
				<idmef:Address category="ipv4-addr-hex">
					<idmef:address>0xde796f70</idmef:address>
				</idmef:Address>
			</idmef:Node>
		</idmef:Target>
		<idmef:Classification text="Teardrop detected">
			<idmef:Reference origin="bugtraqid">
				<idmef:name>124</idmef:name>
				<idmef:url>http://www.securityfocus.com/bid/124</idmef:url>
			</idmef:Reference>
		</idmef:Classification>
	</idmef:Alert>
</idmef:IDMEF-Message>`
}

/*

<?xml version="1.0" encoding="UTF-8"?>
<idmef:IDMEF-Message
	xmlns:idmef="http://iana.org/idmef"
                        version="1.0">
	<idmef:Alert messageid="abc123456789">
		<idmef:Analyzer analyzerid="hq-dmz-analyzer01">
			<idmef:Node category="dns">
				<idmef:location>Headquarters DMZ Network</idmef:location>
				<idmef:name>analyzer01.example.com</idmef:name>
			</idmef:Node>
		</idmef:Analyzer>
		<idmef:CreateTime ntpstamp="0xbc723b45.0xef449129">
         2000-03-09T10:01:25.93464-05:00
       </idmef:CreateTime>
		<idmef:Source ident="a1b2c3d4">
			<idmef:Node ident="a1b2c3d4-001" category="dns">
				<idmef:name>badguy.example.net</idmef:name>
				<idmef:Address ident="a1b2c3d4-002"
                          category="ipv4-net-mask">
					<idmef:address>192.0.2.50</idmef:address>
					<idmef:netmask>255.255.255.255</idmef:netmask>
				</idmef:Address>
			</idmef:Node>
		</idmef:Source>
		<idmef:Target ident="d1c2b3a4">
			<idmef:Node ident="d1c2b3a4-001" category="dns">
				<idmef:Address category="ipv4-addr-hex">
					<idmef:address>0xde796f70</idmef:address>
				</idmef:Address>
			</idmef:Node>
		</idmef:Target>
		<idmef:Classification text="Teardrop detected">
			<idmef:Reference origin="bugtraqid">
				<idmef:name>124</idmef:name>
				<idmef:url>http://www.securityfocus.com/bid/124</idmef:url>
			</idmef:Reference>
		</idmef:Classification>
	</idmef:Alert>
</idmef:IDMEF-Message>
*/
