package commands

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// ParseDuration from Prometheus that supports days, weeks, months, years, unlike the
// stdlib time.ParseDuration (because days are not always the same length, but we can get close
// enough for our purposes in this app.
// https://github.com/prometheus/common/blob/317b7b125e8fddda956d0c9574e5f03f438ed5bc/model/time.go#L188

// original license:
//
// Copyright 2013 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var durationRE = regexp.MustCompile("^(([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?$")

// ParseDuration parses a string into a time.Duration, assuming that a year
// always has 365d, a week always has 7d, and a day always has 24h.
func ParseDuration(durationStr string) (time.Duration, error) {
	switch durationStr {
	case "0":
		// Allow 0 without a unit.
		return 0, nil
	case "":
		return 0, fmt.Errorf("empty duration string")
	}
	matches := durationRE.FindStringSubmatch(durationStr)
	if matches == nil {
		return 0, fmt.Errorf("not a valid duration string: %q", durationStr)
	}
	var dur time.Duration

	// Parse the match at pos `pos` in the regex and use `mult` to turn that
	// into ms, then add that value to the total parsed duration.
	m := func(pos int, mult time.Duration) {
		if matches[pos] == "" {
			return
		}
		n, _ := strconv.Atoi(matches[pos])
		d := time.Duration(n) * time.Millisecond
		dur += d * mult
	}

	m(2, 1000*60*60*24*365) // y
	m(4, 1000*60*60*24*7)   // w
	m(6, 1000*60*60*24)     // d
	m(8, 1000*60*60)        // h
	m(10, 1000*60)          // m
	m(12, 1000)             // s
	m(14, 1)                // ms

	return dur, nil
}
