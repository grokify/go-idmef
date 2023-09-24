package testdata

import (
	"time"

	idmef "github.com/grokify/go-idmef"
)

// ExampleLocalAttacksLoadModuleAttack provides the sample file from
// https://datatracker.ietf.org/doc/html/rfc4765#section-7.3.3
func ExampleLocalAttacksLoadModuleAttack() *idmef.Message {
	dt, err := time.Parse(time.RFC3339, "2000-03-09T08:12:32.3-05:00")
	if err != nil {
		panic(err)
	}
	msg := &idmef.Message{
		XMLNSIDMEF: idmef.XMLNSIDMEFURL,
		Version:    idmef.XMLNSIDMEFVersion,
		Alert: &idmef.Alert{
			MessageID: "abc123456789",
			Analyzer: idmef.Analyzer{
				AnalyzerID: "bc-fs-sensor13",
				Node: &idmef.Node{
					Category: idmef.ServiceDNS,
					Name:     "fileserver.example.com",
				},
				Process: &idmef.Process{
					Name: "monitor",
					PID:  8956,
					Arg: []string{
						"monitor", "-d", "-m", "idmanager.example.com", "-l", "/var/logs/idlog",
					},
				},
			},
			CreateTime: idmef.NewTime(dt),
			Source: []idmef.Source{
				{
					Ident: "a1a2",
					User: &idmef.User{
						Ident:    "a1a2-01",
						Category: idmef.CategoryOSDevice,
						UserID: []idmef.UserID{{
							Ident:  "a1a2-02",
							Type:   idmef.UserIDTypeOriginalUser,
							Name:   "joe",
							Number: "13243",
						}},
					},
					Process: &idmef.Process{
						Ident: "a1a2-03",
						Name:  "loadmodule",
						Path:  "/usr/openwin/bin",
					},
				},
			},
			Target: []idmef.Target{
				{
					Ident: "z3z4",
					Node: &idmef.Node{
						Ident:    "z3z4-01",
						Category: idmef.ServiceDNS,
						Name:     "fileserver.example.com",
					},
				},
			},
			Classification: idmef.Classification{
				Ident: "loadmodule",
				Text:  "Loadmodule attack",
				Reference: []idmef.Reference{
					{
						Origin: "bugtraqid",
						Name:   "33",
						URL:    "http://www.securityfocus.com",
					},
				},
			},
		},
	}
	return msg
}

func ExampleLocalAttacksLoadModuleAttackString() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
	<idmef:IDMEF-Message version="1.0"
		xmlns:idmef="http://iana.org/idmef">
		<idmef:Alert messageid="abc123456789">
			<idmef:Analyzer analyzerid="bc-fs-sensor13">
				<idmef:Node category="dns">
					<idmef:name>fileserver.example.com</idmef:name>
				</idmef:Node>
				<idmef:Process>
					<idmef:name>monitor</idmef:name>
					<idmef:pid>8956</idmef:pid>
					<idmef:arg>monitor</idmef:arg>
					<idmef:arg>-d</idmef:arg>
					<idmef:arg>-m</idmef:arg>
					<idmef:arg>idmanager.example.com</idmef:arg>
					<idmef:arg>-l</idmef:arg>
					<idmef:arg>/var/logs/idlog</idmef:arg>
				</idmef:Process>
			</idmef:Analyzer>
			<idmef:CreateTime ntpstamp="0xbc7221c0.0x4ccccccc">2000-03-09T08:12:32.3-05:00</idmef:CreateTime>
			<idmef:Source ident="a1a2">
				<idmef:User ident="a1a2-01" category="os-device">
					<idmef:UserId ident="a1a2-02"
							 type="original-user">
						<idmef:name>joe</idmef:name>
						<idmef:number>13243</idmef:number>
					</idmef:UserId>
				</idmef:User>
				<idmef:Process ident="a1a2-03">
					<idmef:name>loadmodule</idmef:name>
					<idmef:path>/usr/openwin/bin</idmef:path>
				</idmef:Process>
			</idmef:Source>
			<idmef:Target ident="z3z4">
				<idmef:Node ident="z3z4-01" category="dns">
					<idmef:name>fileserver.example.com</idmef:name>
				</idmef:Node>
			</idmef:Target>
			<idmef:Classification text="Loadmodule attack"
								 ident="loadmodule">
				<idmef:Reference origin="bugtraqid">
					<idmef:name>33</idmef:name>
					<idmef:url>http://www.securityfocus.com</idmef:url>
				</idmef:Reference>
			</idmef:Classification>
		</idmef:Alert>
	</idmef:IDMEF-Message>`
}
