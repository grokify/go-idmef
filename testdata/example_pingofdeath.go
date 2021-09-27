package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// SampleAlert provides the sample file from
// https://en.wikipedia.org/wiki/Intrusion_Detection_Message_Exchange_Format
func SampleAlert() *idmef.Message {
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
					Category: "dns",
					Name:     "sensor.example.com",
				},
			},
			CreateTime: idmef.Time{
				Time:     dt,
				NtpStamp: "0xbc71f4f5.0xef449129",
			},
			Source: []idmef.Source{
				{
					Indent:  "a1a2",
					Spoofed: "yes",
					Node: &idmef.Node{
						Indent: "a1a2-1",
						Address: &idmef.Address{
							Indent:   "a1a2-2",
							Category: "ipv4-addr",
							Address:  "192.0.2.200",
						},
					},
				},
			},
			Target: []idmef.Source{
				{
					Indent: "b3b4",
					Node: &idmef.Node{
						Address: &idmef.Address{
							Indent:   "b3b4-1",
							Category: "ipv4-addr",
							Address:  "192.0.2.50",
						},
					},
				},
				{
					Indent: "c5c6",
					Node: &idmef.Node{
						Indent:   "c5c6-1",
						Category: "nisplus",
						Name:     "lollipop",
					},
				},
				{
					Indent: "d7d8",
					Node: &idmef.Node{
						Indent:   "d7d8-1",
						Location: "Cabinet B10",
						Name:     "Cisco.router.b10",
					},
				},
			},
			Classification: idmef.Classification{
				Text: "Ping-of-death detected",
				Reference: &idmef.Reference{
					Origin: "cve",
					Name:   "CVE-1999-128",
					URL:    "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-128",
				},
			},
		},
	}
	msg.Alert.CreateTime.InflateNtpStamp()
	return msg
}
