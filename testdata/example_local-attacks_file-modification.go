package testdata

import (
	"time"

	"github.com/grokify/go-idmef"
)

// ExampleLocalAttacksFileModification provides the sample file from
// https://datatracker.ietf.org/doc/html/rfc4765#section-7.3.3
func ExampleLocalAttacksFileModification() *idmef.Message {
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
				OSType:     "Linux",
				OSVersion:  "2.2.16-3",
				Node: &idmef.Node{
					Category: "hosts",
					Name:     "etude",
					Address: &idmef.Address{
						Category: idmef.IPV4Addr,
						Address:  "192.0.2.1",
					},
				},
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
								Name:   "fred",
								Number: "456",
							},
							{
								Type:   idmef.UserIdTypeUserPrivs,
								Number: "456",
							},
						},
					},
					File: &idmef.File{
						Category: "current",
						FSType:   "tmpfs",
						Name:     "xxx000238483",
						Path:     "/tmp/xxx000238483",
						FileAccess: []idmef.FileAccess{
							{
								UserId: &idmef.UserId{
									Type:   idmef.UserIdTypeUserPrivs,
									Name:   "alice",
									Number: "777",
								},
								Permission: []idmef.Permission{
									{Perms: "read"},
									{Perms: "write"},
									{Perms: "delete"},
									{Perms: "changePermissions"},
								},
							},
							{
								UserId: &idmef.UserId{
									Type:   idmef.UserIdTypeGroupPrivs,
									Name:   "user",
									Number: "42",
								},
								Permission: []idmef.Permission{
									{Perms: "read"},
									{Perms: "write"},
									{Perms: "delete"},
								},
							},
							{
								UserId: &idmef.UserId{
									Type: "other-privs",
									Name: "world",
								},
								Permission: []idmef.Permission{
									{Perms: "noAccess"},
								},
							},
						},
						Linkage: &idmef.Linkage{
							Category: "symbolic-link",
							Name:     "passwd",
							Path:     "/etc/passwd",
						},
					},
				},
			},
			Classification: idmef.Classification{
				Text: "DOM race condition",
				Reference: []idmef.Reference{
					{
						Origin: idmef.OriginVendorSpecific,
						Name:   "DOM race condition",
						URL:    "file://attack-info/race.html",
					},
				},
			},
		},
	}
	return msg
}

func ExampleLocalAttacksFileModificationString() string {
	return `<idmef:IDMEF-Message version="1.0"
	xmlns:idmef="http://iana.org/idmef">
	<idmef:Alert>
		<idmef:Analyzer analyzerid="bids-192.0.2.1"
                       ostype="Linux"
                       osversion="2.2.16-3">
			<idmef:Node category="hosts">
				<idmef:name>etude</idmef:name>
				<idmef:Address category="ipv4-addr">
					<idmef:address>192.0.2.1</idmef:address>
				</idmef:Address>
			</idmef:Node>
		</idmef:Analyzer>
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
					<idmef:name>fred</idmef:name>
					<idmef:number>456</idmef:number>
				</idmef:UserId>
				<idmef:UserId type="user-privs">
					<idmef:number>456</idmef:number>
				</idmef:UserId>
			</idmef:User>
			<idmef:File category="current" fstype="tmpfs">
				<idmef:name>xxx000238483</idmef:name>
				<idmef:path>/tmp/xxx000238483</idmef:path>
				<idmef:FileAccess>
					<idmef:UserId type="user-privs">
						<idmef:name>alice</idmef:name>
						<idmef:number>777</idmef:number>
					</idmef:UserId>
					<idmef:permission perms="read" />
					<idmef:permission perms="write" />
					<idmef:permission perms="delete" />
					<idmef:permission perms="changePermissions" />
				</idmef:FileAccess>
				<idmef:FileAccess>
					<idmef:UserId type="group-privs">
						<idmef:name>user</idmef:name>
						<idmef:number>42</idmef:number>
					</idmef:UserId>
					<idmef:permission perms="read" />
					<idmef:permission perms="write" />
					<idmef:permission perms="delete" />
				</idmef:FileAccess>
				<idmef:FileAccess>
					<idmef:UserId type="other-privs">
						<idmef:name>world</idmef:name>
					</idmef:UserId>
					<idmef:permission perms="noAccess" />
				</idmef:FileAccess>
				<idmef:Linkage category="symbolic-link">
					<idmef:name>passwd</idmef:name>
					<idmef:path>/etc/passwd</idmef:path>
				</idmef:Linkage>
			</idmef:File>
		</idmef:Target>
		<idmef:Classification text="DOM race condition">
			<idmef:Reference origin="vendor-specific">
				<idmef:name>DOM race condition</idmef:name>
				<idmef:url>file://attack-info/race.html
           </idmef:url>
			</idmef:Reference>
		</idmef:Classification>
	</idmef:Alert>
</idmef:IDMEF-Message>`
}
