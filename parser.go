package iovationsnarego

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	fcFunc       = `__\w\w_\w\w`
	iggyRegex    = regexp.MustCompile(fcFunc + `\("IGGY"\s*,\s*"([^"]+)"\)`)
	svrtimeRegex = regexp.MustCompile(fcFunc + `\("SVRTIME"\s*,\s*"([^"]+)"\)`)
	jssrcRegex   = regexp.MustCompile(fcFunc + `\("JSSRC"\s*,\s*\w+\.` + fcFunc + `\("([^"]+)"\)\)`)
	jstokenRegex = regexp.MustCompile(fcFunc + `\("JSTOKEN"\s*,\s*"([^"]+)"\)`)
	flrtdRegex   = regexp.MustCompile(fcFunc + `\("FLRTD"\s*,\s*"([^"]+)"\)`)
	suagtRegex   = regexp.MustCompile(`decodeURIComponent\("(Mozilla[^"]+)"\)`)
	hacclngRegex = regexp.MustCompile(fcFunc + `\("HACCLNG"\s*,\s*decodeURIComponent\("([^"]+)"\)`)
	jsverRegex   = regexp.MustCompile(fcFunc + `\("JSVER"\s*,\s*"([^"]+)"\)`)
	deskeyRegex  = regexp.MustCompile(`String\.fromCharCode\((0x[0-9a-fA-F]+(?:\s*,\s*0x[0-9a-fA-F]+)*)\)`)
	snareRegex   = regexp.MustCompile(`\.src\s*=\s*'(https://[^']+snare[^']*)'`)
)

// ParseSnareJS extracts all build-specific config values from a snare.js source body.
func ParseSnareJS(jsBody string) (*SnareConfig, error) {
	config := &SnareConfig{}

	// IGGY
	if m := iggyRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		config.IGGY = m[1]
	} else {
		return nil, fmt.Errorf("failed to extract IGGY from snare.js")
	}

	// SVRTIME
	if m := svrtimeRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		config.SVRTIME = m[1]
	} else {
		return nil, fmt.Errorf("failed to extract SVRTIME from snare.js")
	}

	// JSSRC (base64 encoded)
	if m := jssrcRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		decoded, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode JSSRC base64: %w", err)
		}
		config.JSSRC = string(decoded)
	} else {
		return nil, fmt.Errorf("failed to extract JSSRC from snare.js")
	}

	// Token (try FLRTD first, fall back to JSTOKEN)
	if m := flrtdRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		config.Token = m[1]
		config.TokenKey = "FLRTD"
	} else if m := jstokenRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		config.Token = m[1]
		config.TokenKey = "JSTOKEN"
	} else {
		return nil, fmt.Errorf("failed to extract FLRTD/JSTOKEN from snare.js")
	}

	// SUAGT (URL encoded)
	if m := suagtRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		decoded, err := url.QueryUnescape(m[1])
		if err != nil {
			config.SUAGT = m[1]
		} else {
			config.SUAGT = decoded
		}
	} else {
		return nil, fmt.Errorf("failed to extract SUAGT from snare.js")
	}

	// HACCLNG (URL encoded)
	if m := hacclngRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		decoded, err := url.QueryUnescape(m[1])
		if err != nil {
			config.HACCLNG = m[1]
		} else {
			config.HACCLNG = decoded
		}
	} else {
		return nil, fmt.Errorf("failed to extract HACCLNG from snare.js")
	}

	// JSVER
	if m := jsverRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		config.JSVER = m[1]
	} else {
		return nil, fmt.Errorf("failed to extract JSVER from snare.js")
	}

	// DES Key
	if m := deskeyRegex.FindStringSubmatch(jsBody); len(m) == 2 {
		hexParts := strings.Split(m[1], ",")
		if len(hexParts) != 8 {
			return nil, fmt.Errorf("expected 8 DES key bytes, got %d", len(hexParts))
		}
		for i, part := range hexParts {
			val, err := strconv.ParseUint(strings.TrimSpace(part), 0, 8)
			if err != nil {
				return nil, fmt.Errorf("failed to parse DES key byte %d: %w", i, err)
			}
			config.DESKey[i] = byte(val)
		}
	} else {
		return nil, fmt.Errorf("failed to extract DES key from snare.js")
	}

	return config, nil
}

// FindSnareURL extracts the snare.js script URL from an HTML body.
func FindSnareURL(pageHTML string) (string, error) {
	if m := snareRegex.FindStringSubmatch(pageHTML); len(m) == 2 {
		return m[1], nil
	}
	return "", fmt.Errorf("snare.js URL not found in page HTML")
}
