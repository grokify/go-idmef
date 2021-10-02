# IDMEF for Go
## Intrusion Detection Message Exchange Format

[![Build Status][build-status-svg]][build-status-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

 [build-status-svg]: https://github.com/grokify/go-idmef/workflows/go%20build/badge.svg
 [build-status-url]: https://github.com/grokify/go-idmef/actions
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/go-idmef
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/go-idmef
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/go-idmef
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/go-idmef
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/go-idmef/blob/master/LICENSE

Go library for authoring and parsing data in IDMEF format ([IETF RFC 4765](https://datatracker.ietf.org/doc/html/rfc4765)).

## Usage

There are two sets of Message structs, one for authoring and one for parsing. The reason is due to Go's lack of support for parsing XML with tag prefixes.

### Authoring

Use the `go-idmef` (`idmef`) package structs to create the `idmef.Message` struct and then call `xml.Marshal()` or `idmef.Message.Bytes()`.

Example messages from the RFC are available in the [`testdata` folder](testdata) in both XML and Go code. These are compared in the tests](unmarshal/)

### Parsing

See [`unmarshal.ReadFile()`](https://pkg.go.dev/github.com/grokify/go-idmef/unmarshal#ReadFile) function for an example to parse aa IDMEF XML file.

## Coverage

- [x] [IDMEF-Message](https://pkg.go.dev/github.com/grokify/go-idmef#Message)
  - [x] [Alert](https://pkg.go.dev/github.com/grokify/go-idmef#Alert)
    - [x] [Analyzer](https://pkg.go.dev/github.com/grokify/go-idmef#Analyzer)
        - [x] [Node](https://pkg.go.dev/github.com/grokify/go-idmef#Node)
          - [x] [Address](https://pkg.go.dev/github.com/grokify/go-idmef#Address)
        - [x] [Process](https://pkg.go.dev/github.com/grokify/go-idmef#Process)
    - [x] [CreateTime](https://pkg.go.dev/github.com/grokify/go-idmef#Time)
    - [x] [DetectTime](https://pkg.go.dev/github.com/grokify/go-idmef#Time)
    - [x] [AnalyzerTime](https://pkg.go.dev/github.com/grokify/go-idmef#Time)
    - [x] [Source](https://pkg.go.dev/github.com/grokify/go-idmef#Source)
      - [x] [Node](https://pkg.go.dev/github.com/grokify/go-idmef#Node)
        - [x] [Address](https://pkg.go.dev/github.com/grokify/go-idmef#Address)
      - [x] [User](https://pkg.go.dev/github.com/grokify/go-idmef#User)
        - [x] [UserId](https://pkg.go.dev/github.com/grokify/go-idmef#UserId)
      - [x] [Process](https://pkg.go.dev/github.com/grokify/go-idmef#Process)
      - [x] [Service](https://pkg.go.dev/github.com/grokify/go-idmef#Service)
    - [x] [Target](https://pkg.go.dev/github.com/grokify/go-idmef#Target)
      - [x] [Node](https://pkg.go.dev/github.com/grokify/go-idmef#Node)
        - [x] [Address](https://pkg.go.dev/github.com/grokify/go-idmef#Address)
      - [x] [User](https://pkg.go.dev/github.com/grokify/go-idmef#User)
        - [x] [UserId](https://pkg.go.dev/github.com/grokify/go-idmef#UserId)
      - [x] [Process](https://pkg.go.dev/github.com/grokify/go-idmef#Process)
      - [x] [Service](https://pkg.go.dev/github.com/grokify/go-idmef#Service)
      - [x] [File](https://pkg.go.dev/github.com/grokify/go-idmef#File)
        - [x] [FileAccess](https://pkg.go.dev/github.com/grokify/go-idmef#Classification)
          - [x] [Permission](https://pkg.go.dev/github.com/grokify/go-idmef#Classification)
        - [x] [Linkage](https://pkg.go.dev/github.com/grokify/go-idmef#Classification)
    - [x] [Classification](https://pkg.go.dev/github.com/grokify/go-idmef#Classification)
      - [x] [Reference](https://pkg.go.dev/github.com/grokify/go-idmef#Reference)
    - [x] [Assessment](https://pkg.go.dev/github.com/grokify/go-idmef#Assessment)
    - [x] [CorrelationAlert](https://pkg.go.dev/github.com/grokify/go-idmef#CorrelationAlert)
    - [x] [AdditionalData](https://pkg.go.dev/github.com/grokify/go-idmef#AdditionalData)
  - [x] [Heartbeat](https://pkg.go.dev/github.com/grokify/go-idmef#Heartbeat)
    - [x] [Analyzer](https://pkg.go.dev/github.com/grokify/go-idmef#Analyzer)
    - [x] [CreateTime](https://pkg.go.dev/github.com/grokify/go-idmef#Time)
    - [x] [AdditionalData](https://pkg.go.dev/github.com/grokify/go-idmef#AdditionalData)

## Examples

The examples in RFC 4765 are included and tested in this repo. Go and XML representations are provided, parsed and compared. The following is a lists of the examples in RFC 4765. RFC descriptions are provided.

- [x] Denial-of-Service Attacks: The following examples show how some common denial-of-service attacks could be represented in the IDMEF.
  - [x] [The "teardrop" Attack](testdata/example_dos_teardrop-attack.go) ([xml](testdata/example_dos_teardrop-attack.xml)):  Network-based detection of the "teardrop" attack.  This shows the basic format of an alert.
  - [x] [The "ping of death" Attack](testdata/example_dos_pingofdeath-attack.go) ([xml](testdata/example_dos_pingofdeath-attack.xml)): Network-based detection of the "ping of death" attack.  Note the identification of multiple targets, and the identification of the source as a spoofed address. NOTE: The URL has been cut to fit the IETF formating requirements.
- [x] Port Scanning Attacks:   The following examples show how some common port scanning attacks could be represented in the IDMEF.
  - [x] [Connection to a Disallowed Service](testdata/example_port-scanning_connection-to-disallowed-service.go) ([xml](testdata/example_port-scanning_connection-to-disallowed-service.xml)): Host-based detection of a policy violation (attempt to obtain information via "finger").  Note the identification of the target service, as well as the originating user (obtained, e.g., through RFC 1413).
  - [x] [Simple Port Scanning](testdata/example_port-scanning_simple-port-scanning.go) ([xml](testdata/example_port-scanning_simple-port-scanning.xml)):  Network-based detection of a port scan.  This shows detection by a single analyzer; see Section 7.5 for the same attack as detected by a correlation engine.  Note the use of <portlist> to show the ports that were scanned.
- [x] Local Attacks: The following examples show how some common local host attacks could
   be represented in the IDMEF.
  - [x] [The "loadmodule" Attack](testdata/example_local-attacks_loadmodule-attack.go) ([xml](testdata/example_local-attacks_loadmodule-attack.xml)): Host-based detection of the "loadmodule" exploit.  This attack involves tricking the "loadmodule" program into running another program; since "loadmodule" is set-user-id "root", the executed program runs with super-user privileges.  Note the use of <User> and <Process> to identify the user attempting the exploit and how he's doing it.
  - [x] [The "loadmodule" Attack with root target user](testdata/example_local-attacks_loadmodule-root-user-attack.go) ([xml](testdata/example_local-attacks_loadmodule-root-user-attack.xml)):  The Intrusion Detection System (IDS) could also indicate that the target user is the "root" user, and show the attempted command; the alert might then look like:
  - [x] [The "phf" Attack](testdata/example_local-attacks_phf-attack.go) ([xml](testdata/example_local-attacks_phf-attack.xml)): Network-based detection of the "phf" attack.  Note the use of the <WebService> element to provide more details about this particular attack.
  - [x] [File Modification](testdata/example_local-attacks_file-modification.go) ([xml](testdata/example_local-attacks_file-modification.xml)): Host-based detection of a race condition attack.  Note the use of the <File> to provide information about the files that are used to perform the attack.
- [x] [System Policy Violation](testdata/example_system-policy-violation.go) ([xml](testdata/example_system-policy-violation.xml)): In this example, logins are restricted to daytime hours.  The alert reports a violation of this policy that occurs when a user logs in a little after 10:00 pm.  Note the use of <AdditionalData> to provide information about the policy being violated.
- [x] [Correlated Alerts](testdata/example_correlated-alerts.go) ([xml](testdata/example_correlated-alerts.xml)):  The following example shows how the port scan alert from [Section 7.2.2](https://datatracker.ietf.org/doc/html/rfc4765#section-7.2.2) could be represented if it had been detected and sent from a correlation engine, instead of a single analyzer.
- [x] [Analyzer Assessments](testdata/example_analyzer-assessments.go) ([xml](testdata/example_analyzer-assessments.xml)): Host-based detection of a successful unauthorized acquisition of root access through the eject buffer overflow.  Note the use of <Assessment> to provide information about the analyzer's evaluation of and reaction to the attack.
- [x] [Heartbeat](testdata/example_heartbeat.go) ([xml](testdata/example_heartbeat.xml)):  This example shows a Heartbeat message that provides "I'm alive and working" information to the manager.  Note the use of <AdditionalData> elements, with "meaning" attributes, to provide some additional information.

## Notes

1. `idmef` is the authoring package and creates XML with the `idmef` tag.
1. `unmarshal` is the parsing package which reads in XML files but does not support the `idmef` tag prefix due to [Go issue 9519](https://github.com/golang/go/issues/9519). Unmarshal or parse a file using `unmarshal` to receive a `*unmarshal.Message` which can then be converted to an authoring struct with `*unmarshal.Message.Common()`.

## References

### IDMEF

* [IETF RFC 4765: Format Details](https://datatracker.ietf.org/doc/html/rfc4765)
* [IETF RFC 4766: Format Requirements](https://datatracker.ietf.org/doc/html/rfc4766)
* [IETF RFC 4767: Recommended Transport Protocol (IDXP)](https://datatracker.ietf.org/doc/html/rfc4767)
* [IDMEF on Wikipedia](https://en.wikipedia.org/wiki/Intrusion_Detection_Message_Exchange_Format)
* [XML Schema-Based Minification for Communication of Security Information and Event](https://www.researchgate.net/publication/266563239_XML_Schema-Based_Minification_for_Communication_of_Security_Information_and_Event)
* [awesome-idmef](https://github.com/SECEF/awesome-idmef)

### Alternative Formats

* OSSEC: https://www.ossec.net/docs/formats/alerts.html
* OSSEM: https://github.com/OTRF/OSSEM

### Go XML situation

1. [encoding/xml: support for XML namespace prefixes](https://github.com/golang/go/issues/9519)
1. [xml namespace prefix issue at go](https://stackoverflow.com/questions/48609596/xml-namespace-prefix-issue-at-go): "To fix that you need to use two structs, one for Unmarshalling and second to Marshalling data"
1. [Unable to parse xml in GO with : in tags](https://stackoverflow.com/questions/34820549/unable-to-parse-xml-in-go-with-in-tags)

### Other Implementations

1. PHP - https://github.com/fpoirotte/php-idmef

### Comparisons

1. [Power of the IDMEF format](https://www.prelude-siem.com/en/power-of-the-idmef-format/)
1. [SDEE vs IDMEF?](https://seclists.org/focus-ids/2004/Mar/75)
1. [Security Log Standard: Still an Open Question](https://www.scip.ch/en/?labs.20180315)

## Credits

1. `timestamp.Timestamp` is based on code from [`github.com/coreos/mantle`](https://github.com/coreos/mantle) under the Apache 2.0 license and MIT compatible. This is a large, archived codebase with many dependencies.
1. `diffmatchpatch` from [`github.com/sergi/go-diff`](https://github.com/sergi/go-diff) is used during development to analyze failed test results.