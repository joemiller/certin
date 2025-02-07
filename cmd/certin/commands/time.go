package commands

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

// ParseDuration from Prometheus that supports days, weeks, months, years, unlike the
// stdlib time.ParseDuration (because days are not always the same length, but we can get close
// enough for our purposes in this app.
// https://github.com/prometheus/common/blob/55b01d164325a0154b3cc1559dc534542e7faa1f/model/time.go

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

func ParseDuration(s string) (time.Duration, error) {
	switch s {
	case "0":
		// Allow 0 without a unit.
		return 0, nil
	case "":
		return 0, errors.New("empty duration string")
	}

	orig := s
	var dur uint64
	lastUnitPos := 0

	for s != "" {
		if !isdigit(s[0]) {
			return 0, fmt.Errorf("not a valid duration string: %q", orig)
		}
		// Consume [0-9]*
		i := 0
		for ; i < len(s) && isdigit(s[i]); i++ { //nolint: revive // copied from upstream
		}
		v, err := strconv.ParseUint(s[:i], 10, 0)
		if err != nil {
			return 0, fmt.Errorf("not a valid duration string: %q", orig)
		}
		s = s[i:]

		// Consume unit.
		for i = 0; i < len(s) && !isdigit(s[i]); i++ { //nolint: revive // copied from upstream
		}
		if i == 0 {
			return 0, fmt.Errorf("not a valid duration string: %q", orig)
		}
		u := s[:i]
		s = s[i:]
		unit, ok := unitMap[u]
		if !ok {
			return 0, fmt.Errorf("unknown unit %q in duration %q", u, orig)
		}
		if unit.pos <= lastUnitPos { // Units must go in order from biggest to smallest.
			return 0, fmt.Errorf("not a valid duration string: %q", orig)
		}
		lastUnitPos = unit.pos
		// Check if the provided duration overflows time.Duration (> ~ 290years).
		if v > 1<<63/unit.mult {
			return 0, errors.New("duration out of range")
		}
		dur += v * unit.mult
		if dur > 1<<63-1 {
			return 0, errors.New("duration out of range")
		}
	}
	if dur > math.MaxInt64 {
		return 0, errors.New("duration out of range")
	}
	return time.Duration(dur), nil
}

func isdigit(c byte) bool { return c >= '0' && c <= '9' }

// Units are required to go in order from biggest to smallest.
// This guards against confusion from "1m1d" being 1 minute + 1 day, not 1 month + 1 day.
var unitMap = map[string]struct {
	pos  int
	mult uint64
}{
	"ms": {7, uint64(time.Millisecond)},
	"s":  {6, uint64(time.Second)},
	"m":  {5, uint64(time.Minute)},
	"h":  {4, uint64(time.Hour)},
	"d":  {3, uint64(24 * time.Hour)},
	"w":  {2, uint64(7 * 24 * time.Hour)},
	"y":  {1, uint64(365 * 24 * time.Hour)},
}
