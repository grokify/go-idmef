package ntp

import (
	"fmt"
	"strconv"
	"time"
)

// EpochNTPSeconds is the Unix Epoch (1970-01-01T00:00:00Z) in NTP Seconds (1970 - 1900)
const EpochNTPSeconds = 2208988800

// Timestamp represents a NTP timestamp. The code is from
// `github.com/coreos/mantle` under the Apache 2.0 license.
type Timestamp struct {
	Seconds  uint32
	Fraction uint32
}

// Now gets the current NTP time in the 64-bit Timestamp format.
func Now() Timestamp {
	return NewTimestamp(time.Now())
}

// NewTimestamp converts from Go's Time to NTP's 64-bit Timestamp format.
func NewTimestamp(t time.Time) Timestamp {
	secs := t.Unix() + EpochNTPSeconds
	// Convert from range [0,999999999] to [0,UINT32_MAX]
	frac := (uint64(t.Nanosecond()) << 32) / 1000000000
	return Timestamp{Seconds: uint32(secs), Fraction: uint32(frac)}
}

func (ts Timestamp) String() string {
	return "0x" + strconv.FormatInt(int64(ts.Seconds), 16) + ".0x" +
		fmt.Sprintf("%08s", strconv.FormatInt(int64(ts.Fraction), 16))
}

func TimeToNTP(t time.Time) string {
	return NewTimestamp(t).String()
}
