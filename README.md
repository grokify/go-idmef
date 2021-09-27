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

## Implementation

- [ ] IDMEF-Message
  - [ ] Alert
    - [x] Analyzer
    - [x] CreateTime
    - [x] DetectTime
    - [x] AnalyzerTime
    - [ ] Source
      - [x] Node
      - [ ] User
      - [ ] Process
      - [ ] Service
    - [ ] Target
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

## References

### IDMEF

* [IETF RFC 4765: Format Details](https://datatracker.ietf.org/doc/html/rfc4765)
* [IETF RFC 4766: Format Requirements](https://datatracker.ietf.org/doc/html/rfc4766)
* [IETF RFC 4767: Recommended Transport Protocol (IDXP)](https://datatracker.ietf.org/doc/html/rfc4767)
* [IDMEF on Wikipedia](https://en.wikipedia.org/wiki/Intrusion_Detection_Message_Exchange_Format)

### Alternative Formats

* OSSEC: https://www.ossec.net/docs/formats/alerts.html
* OSSEM: https://github.com/OTRF/OSSEM

## Credits

`timestamp.Timestamp` is based on code from `github.com/coreos/mantle` under the Apache 2.0 license. This is a large, archived
codebase with many dependencies.