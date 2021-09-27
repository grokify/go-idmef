package idmef

import (
	"time"
)

// SampleAlert provides the sample file from
// https://en.wikipedia.org/wiki/Intrusion_Detection_Message_Exchange_Format
func SampleAlert() Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T10:01:25.93464Z")
	if err != nil {
		panic(err)
	}
	return Message{
		XMLNSIDMEF: XMLNSIDMEFUrl,
		Version:    XMLNSIDMEFVersion,
		Alert: &Alert{
			MessageId: "abc123456789",
			Analyzer: &Analyzer{
				AnalyzerId: "bc-sensor01",
				Node: &Node{
					Category: "dns",
					Name:     "sensor.example.com",
				},
			},
			CreateTime: &Time{
				Time:     dt,
				NtpStamp: "0xbc71f4f5.0xef449129",
			},
			Source: &Source{
				Indent:  "a1a2",
				Spoofed: "yes",
				Node: &Node{
					Indent: "a1a2-1",
					Address: &Address{
						Indent:   "a1a2-2",
						Category: "ipv4-addr",
						Address:  "192.0.2.200",
					},
				},
			},
			Target: []*Source{
				{
					Indent: "b3b4",
					Node: &Node{
						Address: &Address{
							Indent:   "b3b4-1",
							Category: "ipv4-addr",
							Address:  "192.0.2.50",
						},
					},
				},
				{
					Indent: "c5c6",
					Node: &Node{
						Indent:   "c5c6-1",
						Category: "nisplus",
						Name:     "lollipop",
					},
				},
				{
					Indent: "d7d8",
					Node: &Node{
						Indent:   "d7d8-1",
						Location: "Cabinet B10",
						Name:     "Cisco.router.b10",
					},
				},
			},
			Classification: &Classification{
				Text: "Ping-of-death detected",
				Reference: &Reference{
					Origin: "cve",
					Name:   "CVE-1999-128",
					URL:    "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-128",
				},
			},
		},
	}
}
