package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// ExampleSystemPolicyViolation provides the sample file from
// https://datatracker.ietf.org/doc/html/rfc4765#section-7.4
func ExampleSystemPolicyViolation() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T22:18:07-05:00")
	if err != nil {
		panic(err)
	}
	startTime, err := time.Parse(time.RFC3339, "2000-03-09T07:00:00-05:00")
	if err != nil {
		panic(err)
	}
	stopTime, err := time.Parse(time.RFC3339, "2000-03-09T19:30:00-05:00")
	if err != nil {
		panic(err)
	}
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFURL,
		Version:    idmef.XMLNSIDMEFVersion,
		Alert: &idmef.Alert{
			MessageID: "abc123456789",
			Analyzer: idmef.Analyzer{
				AnalyzerID: "bc-ds-01",
				Node: &idmef.Node{
					Category: idmef.ServiceDNS,
					Name:     "dialserver.example.com",
				},
			},
			CreateTime: idmef.NewTime(dt),
			Source: []idmef.Source{
				{
					Ident: "s01",
					Node: &idmef.Node{
						Ident: "s01-1",
						Address: &idmef.Address{
							Category: idmef.IPV4Addr,
							Address:  "127.0.0.1",
						},
					},
					Service: &idmef.Service{
						Ident: "s01-2",
						Port:  4325,
					},
				},
			},
			Target: []idmef.Target{
				{
					Ident: "t01",
					Node: &idmef.Node{
						Ident:    "t01-1",
						Category: idmef.ServiceDNS,
						Name:     "mainframe.example.com",
					},
					User: &idmef.User{
						Ident:    "t01-2",
						Category: idmef.CategoryOSDevice,
						UserID: []idmef.UserID{{
							Ident:  "t01-3",
							Type:   idmef.UserIDTypeCurrentUser,
							Name:   "louis",
							Number: "501",
						}},
					},
					Service: &idmef.Service{
						Ident: "t01-4",
						Name:  idmef.ServiceLogin,
						Port:  23,
					},
				},
			},
			Classification: idmef.Classification{
				Text: "Login policy violation",
				Reference: []idmef.Reference{
					{
						Origin: idmef.OriginUserSpecific,
						Name:   "out-of-hours activity",
						URL:    "http://my.company.com/policies",
					},
				},
			},
			AdditionalData: []idmef.AdditionalData{
				{
					Type:     idmef.DateTime,
					Meaning:  idmef.StartTime,
					DateTime: startTime,
				},
				{
					Type:     idmef.DateTime,
					Meaning:  idmef.StopTime,
					DateTime: stopTime,
				},
			},
		},
	}
	return msg
}

func ExampleSystemPolicyViolationString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<idmef:IDMEF-Message version="1.0"
	xmlns:idmef="http://iana.org/idmef">
	<idmef:Alert messageid="abc123456789">
		<idmef:Analyzer analyzerid="bc-ds-01">
			<idmef:Node category="dns">
				<idmef:name>dialserver.example.com</idmef:name>
			</idmef:Node>
		</idmef:Analyzer>
		<idmef:CreateTime ntpstamp="0xbc72e7ef.0x00000000">2000-03-09T22:18:07-05:00</idmef:CreateTime>
		<idmef:Source ident="s01">
			<idmef:Node ident="s01-1">
				<idmef:Address category="ipv4-addr">
					<idmef:address>127.0.0.1</idmef:address>
				</idmef:Address>
			</idmef:Node>
			<idmef:Service ident="s01-2">
				<idmef:port>4325</idmef:port>
			</idmef:Service>
		</idmef:Source>
		<idmef:Target ident="t01">
			<idmef:Node ident="t01-1" category="dns">
				<idmef:name>mainframe.example.com</idmef:name>
			</idmef:Node>
			<idmef:User ident="t01-2" category="os-device">
				<idmef:UserId ident="t01-3" type="current-user">
					<idmef:name>louis</idmef:name>
					<idmef:number>501</idmef:number>
				</idmef:UserId>
			</idmef:User>
			<idmef:Service ident="t01-4">
				<idmef:name>login</idmef:name>
				<idmef:port>23</idmef:port>
			</idmef:Service>
		</idmef:Target>
		<idmef:Classification text="Login policy violation">
			<idmef:Reference origin="user-specific">
				<idmef:name>out-of-hours activity</idmef:name>
				<idmef:url>http://my.company.com/policies
           </idmef:url>
			</idmef:Reference>
		</idmef:Classification>
		<idmef:AdditionalData type="date-time"
                             meaning="start-time">
			<idmef:date-time>2000-03-09T07:00:00-05:00</idmef:date-time>
		</idmef:AdditionalData>
		<idmef:AdditionalData type="date-time"
                             meaning="stop-time">
			<idmef:date-time>2000-03-09T19:30:00-05:00</idmef:date-time>
		</idmef:AdditionalData>
	</idmef:Alert>
</idmef:IDMEF-Message>`
}
