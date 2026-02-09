package iovationsnarego

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type BlackboxGenerator struct {
	Verbose      bool
	Debug        bool
	config       *SnareConfig
	randInstance *rand.Rand
}

func NewBlackboxGenerator(config *SnareConfig, verbose, debug bool) (*BlackboxGenerator, error) {
	g := &BlackboxGenerator{randInstance: rand.New(rand.NewSource(time.Now().UnixNano())), config: config, Verbose: verbose, Debug: debug}
	if err := g.validateConfig(); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *BlackboxGenerator) validateConfig() error {
	if g.config == nil {
		return errors.New("invalid config: snare config not defined")
	}
	if g.config.IGGY == "" {
		return errors.New("invalid config: IGGY not defined")
	}
	if g.config.JSSRC == "" {
		return errors.New("invalid config: JSSRC not defined")
	}
	if g.config.BBOUT == "" {
		return errors.New("invalid config: BBOUT not defined (io_bbout_element_id)")
	}
	if g.config.SVRTIME == "" {
		return errors.New("invalid config: SVRTIME not defined")
	}
	if g.config.Token == "" {
		return errors.New("invalid config: Token not defined")
	}
	if g.config.TokenKey == "" {
		return errors.New("invalid config: Token key not defined (FLRTD or JSTOKEN)")
	}
	if g.config.SUAGT == "" {
		return errors.New("invalid config: SUAGT not defined")
	}
	if g.config.HACCLNG == "" {
		return errors.New("invalid config: HACCLNG not defined")
	}
	if g.config.JSVER == "" {
		return errors.New("invalid config: JSVER not defined")
	}
	if g.config.DESKey == [8]byte{} {
		return errors.New("invalid config: DES key not defined")
	}
	return nil
}

// Generate produces an ioBlackBox fingerprint string from the given parameters.
func (g *BlackboxGenerator) Generate(params *BlackboxParams) string {
	g.verboseLog(LogInfo, "generating blackbox fingerprint")

	ua := params.UserAgent
	if len(ua) > 400 {
		ua = ua[:400]
	}

	browserName, browserVersion, osName, jbrcm := ParseUA(ua)
	g.debugLog(fmt.Sprintf("parsed UA: browser=%s version=%s os=%s jbrcm=%s", browserName, browserVersion, osName, jbrcm))

	// Build page URL without query params
	pageURL := params.PageURL
	if idx := strings.Index(pageURL, "?"); idx != -1 {
		pageURL = pageURL[:idx]
	}

	// Build appVersion from UA (everything after "Mozilla/")
	appVersion := ua
	if idx := strings.Index(ua, "Mozilla/"); idx != -1 {
		appVersion = ua[idx+len("Mozilla/"):]
	}

	// Timezone offset: take the max of Jan/Jul offsets (DST handling)
	tzOffset := fmt.Sprintf("%d", params.TimezoneOffset)

	// Random plausibile resolution
	var resolution = params.Resolution
	if resolution == nil {
		resolution = resolutions[g.randInstance.Intn(len(resolutions))]
	}

	// Current UTC time
	jsTime := time.Now().UTC().Format("2006/01/02 15:04:05")

	// __if_fc skips undefined and empty-string values — match that behavior
	var kvs []KVPair
	add := func(key, value string) {
		if value != "" {
			kvs = append(kvs, KVPair{key, value})
		}
	}

	// Field order matches snare.js internal dictionary insertion order.
	// The JS object preserves property insertion order (V8), and toString iterates it.

	// Init phase: these are set during snare.js initialization, before data collection
	add(g.config.TokenKey, g.config.Token)
	add("INTLOC", pageURL)
	add("JINT", string(params.IntegrationType))

	// Data collection phase: io_dp.__if_op populates browser fingerprint fields
	add("JENBL", "1")
	add("JSSRC", g.config.JSSRC)
	add("UAGT", ua)

	// UA spoofing detection: only set when actual UA differs from the expected UA baked into snare.js
	if g.config.SUAGT != "" && ua != g.config.SUAGT {
		add("JDIFF", "1")
		add("SUAGT", g.config.SUAGT)
	}

	add("HACCLNG", g.config.HACCLNG)
	// HACCCHR: Accept-Charset — undefined in modern Chrome, __if_fc skips it
	add("JSVER", g.config.JSVER)
	add("TZON", tzOffset)
	add("JSTIME", jsTime)
	add("SVRTIME", g.config.SVRTIME)
	add("JBRNM", browserName)
	add("JBRVR", browserVersion)
	add("JBROS", osName)
	add("BBOUT", g.config.BBOUT)
	// FHAT: window.IGLOO.fnuhType — undefined in Chrome, __if_fc skips it
	add("APVER", appVersion)
	add("APNAM", "Netscape")
	// OSCPU: navigator.oscpu — undefined in Chrome (Firefox-only), __if_fc skips it
	add("NPLAT", params.Platform)
	add("JBRCM", jbrcm)
	add("JLANG", params.Language)
	// JCOX: navigator.cookieEnabled — only set to "1" when cookies disabled, otherwise skipped
	add("IGGY", g.config.IGGY)
	add("JRES", fmt.Sprintf("%dx%d", resolution.Height, resolution.Width))
	// JSMBR: mobile browser detection — empty on desktop, __if_fc skips it
	// XREQW: XMLHttpRequest/WebSocket probe — empty, __if_fc skips it
	add("JPLGNS", "internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;")
	add("JREFRR", params.Referer)

	// Serialize
	serialized := SerializeKVs(kvs)
	g.debugLog(fmt.Sprintf("serialized %d fields (%d chars)", len(kvs), len(serialized)))

	// DES-ECB encrypt
	ciphertext, err := DesECBEncrypt(g.config.DESKey, []byte(serialized))
	if err != nil {
		g.log(LogError, fmt.Sprintf("DES encryption failed: %v", err))
		return ""
	}

	// Base64 encode + version prefix
	encoded := base64Encode(ciphertext)
	blackbox := "0400" + encoded

	g.verboseLog(LogInfo, fmt.Sprintf("generated blackbox (%d chars)", len(blackbox)))
	return blackbox
}
