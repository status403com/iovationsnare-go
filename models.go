package iovationsnarego

type IntegrationType string

const (
	Callback IntegrationType = "callback" // window.io_bb_callback is a function — the page registered a JS callback to receive the blackbox
	Form     IntegrationType = "form"     // No callback — snare.js writes the blackbox directly into the hidden <input> element (the GlobalE case)
	Function IntegrationType = "function" // ioGetBlackbox() was called explicitly — someone invoked the public API to retrieve the blackbox on demand
)

// SnareConfig holds the build-specific constants extracted from a site's snare.js.
// These values are baked into each snare.js build and differ per site/merchant.
type SnareConfig struct {
	IGGY     string  // 64-char hex subscriber/merchant identifier — routes blackbox to the correct Iovation fraud rules
	JSSRC    string  // CDN/server identifier for this snare.js deployment (base64-decoded from __if_fc("JSSRC",...))
	BBOUT    string  // io_bbout_element_id
	SVRTIME  string  // server-side build timestamp (YYYY/MM/DD HH:MM:SS) — paired with JSTIME for freshness/replay detection
	Token    string  // first-load real-time detection token value — ties blackbox to a specific script load event
	TokenKey string  // key name for the token field ("FLRTD" when from iesnare CDN, "JSTOKEN" when 3rd-party hosted)
	SUAGT    string  // expected User-Agent baked into this build — compared with actual UA to detect spoofing
	HACCLNG  string  // expected Accept-Language baked into this build — cross-referenced with language and timezone for geo-consistency
	JSVER    string  // snare.js SDK version (e.g. "3.1.3") — tells server which serialization format to expect
	DESKey   [8]byte // 8-byte DES-ECB encryption key parsed from String.fromCharCode() in snare.js
}

// BlackboxParams holds the per-request dynamic values for blackbox generation.
type BlackboxParams struct {
	UserAgent       string          // browser User-Agent string (truncated to 400 chars)
	PageURL         string          // current page URL (no query params)
	Referer         string          // document.referer
	Language        string          // browser language (e.g. "en-US")
	Platform        string          // browser navigator.platform
	Resolution      *Resolution     // screen resolution
	TimezoneOffset  int             // timezone offset in minutes (e.g. -60 for UTC+1)
	IntegrationType IntegrationType // script integration type
}

type Resolution struct {
	Width  int
	Height int
}
