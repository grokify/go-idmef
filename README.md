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

Go library for authoring and parsing data in
IDMEF format (IETF RFC 4765).

## Usage

There are two sets of Message structs, one for authoring and one for parsing. The reason is due to Go's lack of support for parsing XML with tag prefixes.

### Authoring

Use the `go-idmef` (`idmef`) package structs to create the `idmef.Message` struct and then call `xml.Marshal()` or `idmef.Message.Bytes()`.

An example is in the [testdata/example_pingofdeath.go](https://github.com/grokify/go-idmef/blob/v0.1.0/testdata/example_pingofdeath.go) file.

### Parsing

See [`unmarshal.ReadFile()`](https://pkg.go.dev/github.com/grokify/go-idmef/unmarshal#ReadFile) function for an example to parse aa IDMEF XML file.

## Coverage

- [x] [IDMEF-Message](https://pkg.go.dev/github.com/grokify/go-idmef#Message)
  - [x] [Alert](https://pkg.go.dev/github.com/grokify/go-idmef#Alert)
    - [x] [Analyzer](https://pkg.go.dev/github.com/grokify/go-idmef#Analyzer)
    - [x] [CreateTime](https://pkg.go.dev/github.com/grokify/go-idmef#Time)
    - [x] [DetectTime](https://pkg.go.dev/github.com/grokify/go-idmef#Time)
    - [x] [AnalyzerTime](https://pkg.go.dev/github.com/grokify/go-idmef#Time)
    - [x] [Source](https://pkg.go.dev/github.com/grokify/go-idmef#Source)
      - [x] [Node](https://pkg.go.dev/github.com/grokify/go-idmef#Node)
        - [x] Address
      - [x] User
        - [x] UserId
      - [x] Process
      - [x] Service
    - [x] Target
      - [x] [Node](https://pkg.go.dev/github.com/grokify/go-idmef#Node)
        - [x] Address
      - [x] User
        - [x] UserId
      - [x] Process
      - [x] Service
      - [x] File
        - [x] FileAccess
          - [x] Permission
        - [x] Linkage
    - [x] [Classification](https://pkg.go.dev/github.com/grokify/go-idmef#Classification)
      - [x] Reference
    - [x] Assessment
    - [x] AdditionalData
  - [ ] Heartbeat
    - [ ] Analyzer
    - [ ] CreateTime
    - [ ] AdditionalData

## Examples

The examples in RFC 4765 are included and tested in this repo. The following is a lists of the examples in RFC 4765. 

- [x] Denial-of-Service Attacks
  - [x] [The "teardrop" Attack](testdata/example_dos_teardrop-attack.go) ([xml](testdata/example_dos_teardrop-attack.xml))
  - [x] [The "ping of death" Attack](testdata/example_dos_pingofdeath-attack.go) ([xml](testdata/example_dos_pingofdeath-attack.xml))
- [ ] Port Scanning Attacks
  - [x] [Connection to a Disallowed Service](testdata/example_port-scanning_connection-to-disallowed-service.go) ([xml](testdata/example_port-scanning_connection-to-disallowed-service.xml))
  - [ ] Simple Port Scanning
- [ ] Local Attacks
  - [ ] The "loadmodule" Attack
  - [ ] The "phf" Attack
  - [x] [File Modification](testdata/example_local-attacks_file-modification.go) ([xml](testdata/example_local-attacks_file-modification.xml))
- [x] [System Policy Violation](testdata/example_system-policy-violataion.go) ([xml](testdata/example_system-policy-violataion.xml))
- [ ] Correlated Alerts
- [x] [Analyzer Assessments](testdata/example_analyzer-assessments.go) ([xml](testdata/example_analyzer-assessments.xml))
- [ ] Heartbeat

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

`timestamp.Timestamp` is based on code from `github.com/coreos/mantle` under the Apache 2.0 license. This is a large, archived
codebase with many dependencies.