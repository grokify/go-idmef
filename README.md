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

## Status

- [x] IDMEF-Message
  - [x] Alert
    - [x] Analyzer
    - [x] CreateTime
    - [x] DetectTime
    - [x] AnalyzerTime
    - [x] Source
      - [x] Node
      - [ ] User
      - [ ] Process
      - [ ] Service
    - [x] Target
      - [x] Node
      - [ ] User
      - [ ] Process
      - [ ] Service
    - [x] Classification
    - [ ] Assessment
    - [ ] AdditionalData
  - [ ] Heartbeat
    - [ ] Analyzer
    - [ ] CreateTime
    - [ ] AdditionalData

## Notes

1. `idmef` is the authoring package and creates XML with the `idmef` tag.
1. `unmarshal` is the parsing package which reads in XML files but does not support the `idmef` tag prefix due to [Go issue 9519](https://github.com/golang/go/issues/9519). Unmarshal or parse a file using `unmarshal` to receive a `*unmarshal.Message` which can then be converted to an authoring struct with `*unmarshal.Message.Common()`.

## References

### IDMEF

* [IETF RFC 4765: Format Details](https://datatracker.ietf.org/doc/html/rfc4765)
* [IETF RFC 4766: Format Requirements](https://datatracker.ietf.org/doc/html/rfc4766)
* [IETF RFC 4767: Recommended Transport Protocol (IDXP)](https://datatracker.ietf.org/doc/html/rfc4767)
* [IDMEF on Wikipedia](https://en.wikipedia.org/wiki/Intrusion_Detection_Message_Exchange_Format)

### Alternative Formats

* OSSEC: https://www.ossec.net/docs/formats/alerts.html
* OSSEM: https://github.com/OTRF/OSSEM

### Go XML situation

1. [encoding/xml: support for XML namespace prefixes](https://github.com/golang/go/issues/9519)
1. [xml namespace prefix issue at go](https://stackoverflow.com/questions/48609596/xml-namespace-prefix-issue-at-go): "To fix that you need to use two structs, one for Unmarshalling and second to Marshalling data"
1. [Unable to parse xml in GO with : in tags](https://stackoverflow.com/questions/34820549/unable-to-parse-xml-in-go-with-in-tags)

## Credits

`timestamp.Timestamp` is based on code from `github.com/coreos/mantle` under the Apache 2.0 license. This is a large, archived
codebase with many dependencies.