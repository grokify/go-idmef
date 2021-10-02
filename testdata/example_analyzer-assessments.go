package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// ExampleAlertAnalyzerAssessment provides the sample file from
// https://en.wikipedia.org/wiki/Intrusion_Detection_Message_Exchange_Format
func ExampleAlertAnalyzerAssessment() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T08:12:32-01:00")
	if err != nil {
		panic(err)
	}
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFUrl,
		Version:    idmef.XMLNSIDMEFVersion,
		Alert: &idmef.Alert{
			Analyzer: idmef.Analyzer{
				AnalyzerId: "bids-192.0.2.1",
			},
			CreateTime: idmef.NewTime(dt),
			Source: []idmef.Source{
				{
					Spoofed: "no",
					Node: &idmef.Node{
						Location: idmef.LocationConsole,
						Address: &idmef.Address{
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.1",
						},
					},
				},
			},
			Target: []idmef.Target{
				{
					Decoy: "no",
					Node: &idmef.Node{
						Location: idmef.LocationLocal,
						Address: &idmef.Address{
							Category: idmef.IPV4Addr,
							Address:  "192.0.2.1",
						},
					},
					User: &idmef.User{
						Category: idmef.CategoryOSDevice,
						UserId: []idmef.UserId{
							{
								Type:   idmef.UserIdTypeOriginalUser,
								Number: "456",
							},
							{
								Type:   idmef.UserIdTypeCurrentUser,
								Name:   "root",
								Number: "0",
							},
							{
								Type:   idmef.UserIdTypeUserPrivs,
								Number: "0",
							},
						},
					},
					Process: &idmef.Process{
						Name: "eject",
						PID:  32451,
						Path: "/usr/bin/eject",
						Arg:  []string{`\x90\x80\x3f\xff...\x08/bin/sh`},
					},
				},
			},
			Classification: idmef.Classification{
				Text: "Unauthorized administrative access",
				Reference: []idmef.Reference{{
					Origin: "vendor-specific",
					Name:   "Unauthorized user to superuser",
					URL:    "file://attack-info/u2s.html",
				}},
			},
			Assessment: &idmef.Assessment{
				Impact: &idmef.Impact{
					Severity:   "high",
					Completion: "succeeded",
					Type:       "admin",
				},
				Action: []idmef.Action{
					{
						Action:   "page",
						Category: "notification-sent"},
					{
						Action:   "disabled user (fred)",
						Category: "block-installed"},
					{
						Action:   "logout user (fred)",
						Category: "taken-offline"},
				},
				Confidence: &idmef.Confidence{
					Rating: "high",
				},
			},
		},
	}
	return msg
}

func ExampleAlertAnalyzerAssessmentString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<idmef:IDMEF-Message version="1.0"
	xmlns:idmef="http://iana.org/idmef">
	<idmef:Alert>
		<idmef:Analyzer analyzerid="bids-192.0.2.1"></idmef:Analyzer>
		<idmef:CreateTime ntpstamp="0xbc71e980.0x00000000">2000-03-09T08:12:32-01:00</idmef:CreateTime>
		<idmef:Source spoofed="no">
			<idmef:Node>
				<idmef:location>console</idmef:location>
				<idmef:Address category="ipv4-addr">
					<idmef:address>192.0.2.1</idmef:address>
				</idmef:Address>
			</idmef:Node>
		</idmef:Source>
		<idmef:Target decoy="no">
			<idmef:Node>
				<idmef:location>local</idmef:location>
				<idmef:Address category="ipv4-addr">
					<idmef:address>192.0.2.1</idmef:address>
				</idmef:Address>
			</idmef:Node>
			<idmef:User category="os-device">
				<idmef:UserId type="original-user">
					<idmef:number>456</idmef:number>
				</idmef:UserId>
				<idmef:UserId type="current-user">
					<idmef:name>root</idmef:name>
					<idmef:number>0</idmef:number>
				</idmef:UserId>
				<idmef:UserId type="user-privs">
					<idmef:number>0</idmef:number>
				</idmef:UserId>
			</idmef:User>
			<idmef:Process>
				<idmef:name>eject</idmef:name>
				<idmef:pid>32451</idmef:pid>
				<idmef:path>/usr/bin/eject</idmef:path>
				<idmef:arg>\x90\x80\x3f\xff...\x08/bin/sh</idmef:arg>
			</idmef:Process>
		</idmef:Target>
		<idmef:Classification
           text="Unauthorized administrative access">
			<idmef:Reference origin="vendor-specific">
				<idmef:name>Unauthorized user to superuser</idmef:name>
				<idmef:url>file://attack-info/u2s.html</idmef:url>
			</idmef:Reference>
		</idmef:Classification>
		<idmef:Assessment>
			<idmef:Impact severity="high" completion="succeeded"
                 type="admin"/>
			<idmef:Action category="notification-sent">
           page
           </idmef:Action>
			<idmef:Action category="block-installed">
           disabled user (fred)
         </idmef:Action>
			<idmef:Action category="taken-offline">
           logout user (fred)
         </idmef:Action>
			<idmef:Confidence rating="high"/>
		</idmef:Assessment>
	</idmef:Alert>
</idmef:IDMEF-Message>`
}
