package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// ExampleHeartbeat provides the sample file from
// https://datatracker.ietf.org/doc/html/draft-ietf-idwg-idmef-xml#section-7.7
func ExampleHeartbeat() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T14:07:58Z")
	if err != nil {
		panic(err)
	}
	memused := float64(62.5)
	diskused := float64(87.1)
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFUrl,
		Version:    idmef.XMLNSIDMEFVersion,
		Heartbeat: &idmef.Heartbeat{
			MessageId: "abc123456789",
			Analyzer: idmef.Analyzer{
				AnalyzerId: "hq-dmz-analyzer01",
				Node: &idmef.Node{
					Category: idmef.ServiceDNS,
					Location: "Headquarters DMZ Network",
					Name:     "analyzer01.example.com",
				},
			},
			CreateTime: idmef.NewTime(dt),
			AdditionalData: []idmef.AdditionalData{
				{
					Type:    idmef.TypeReal,
					Meaning: "%memused",
					Real:    &memused},
				{
					Type:    idmef.TypeReal,
					Meaning: "%diskused",
					Real:    &diskused},
			},
		},
	}
	return msg
}

func ExampleHeartbeatString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
	<idmef:IDMEF-Message version="1.0"
		xmlns:idmef="http://iana.org/idmef">
		<idmef:Heartbeat messageid="abc123456789">
			<idmef:Analyzer analyzerid="hq-dmz-analyzer01">
				<idmef:Node category="dns">
					<idmef:location>Headquarters DMZ Network</idmef:location>
					<idmef:name>analyzer01.example.com</idmef:name>
				</idmef:Node>
			</idmef:Analyzer>
			<idmef:CreateTime ntpstamp="0xbc722ebe.0x00000000">2000-03-09T14:07:58Z</idmef:CreateTime>
			<idmef:AdditionalData type="real" meaning="%memused">
				<idmef:real>62.5</idmef:real>
			</idmef:AdditionalData>
			<idmef:AdditionalData type="real" meaning="%diskused">
				<idmef:real>87.1</idmef:real>
			</idmef:AdditionalData>
		</idmef:Heartbeat>
	</idmef:IDMEF-Message>`
}
