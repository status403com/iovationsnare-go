package test

import (
	iovationsnarego "github.com/status403com/iovationsnare-go"
	"crypto/des"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Pokemon Center GlobalE snare.js build config (hardcoded values from the actual snare.js).
// If these change, re-run ParseSnareJS on the latest snare.js body.
var testConfig = &iovationsnarego.SnareConfig{
	IGGY:     "ajhX8U8YHxOyzdXEDGbRRazTg5OktIgQ4lN3PpeFbdPcPWTmwbnv9GX54KydaIMo",
	JSSRC:    "am1prwdp03.iovation.us",
	BBOUT:    "ioBlackBox",
	SVRTIME:  "2018/11/28 11:57:02",
	Token:    "/eYbIxrn3mAExmFkurAILblYjwPfFgzes7T1pLQbJMI=",
	TokenKey: "FLRTD",
	SUAGT:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
	HACCLNG:  "en-IL,en-US;q=0.8,en;q=0.5,he;q=0.3",
	JSVER:    "3.1.3",
	DESKey:   [8]byte{0x7c, 0x4c, 0x45, 0x00, 0x63, 0x02, 0xc8, 0xa3},
}

// TestSerializeKVs verifies the hex-length-prefixed serialization matches snare.js format.
func TestSerializeKVs(t *testing.T) {
	kvs := []iovationsnarego.KVPair{
		{Key: "JENBL", Value: "1"},
		{Key: "UAGT", Value: "TestAgent"},
	}

	result := iovationsnarego.SerializeKVs(kvs)

	// Expected: hex4(2) + hex4(5) + "JENBL" + hex4(1) + "1" + hex4(4) + "UAGT" + hex4(9) + "TestAgent"
	//         = "0002" + "0005" + "JENBL" + "0001" + "1" + "0004" + "UAGT" + "0009" + "TestAgent"
	expected := "00020005JENBL000110004UAGT0009TestAgent"

	if result != expected {
		t.Errorf("SerializeKVs mismatch:\n  got:    %s\n  expect: %s", result, expected)
	}
}

// TestSerializeKVsUppercasesKeys verifies keys are uppercased during serialization.
func TestSerializeKVsUppercasesKeys(t *testing.T) {
	kvs := []iovationsnarego.KVPair{
		{Key: "jlang", Value: "en-US"},
	}

	result := iovationsnarego.SerializeKVs(kvs)
	expected := "00010005JLANG0005en-US"

	if result != expected {
		t.Errorf("Key not uppercased:\n  got:    %s\n  expect: %s", result, expected)
	}
}

// TestDESECBEncryptDecrypt verifies DES-ECB round-trip with the known snare.js key.
func TestDESECBEncryptDecrypt(t *testing.T) {
	key := testConfig.DESKey
	plaintext := []byte("hello123") // exactly 8 bytes, no padding needed

	ciphertext, err := iovationsnarego.DesECBEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("DesECBEncrypt failed: %v", err)
	}

	if len(ciphertext) != 8 {
		t.Fatalf("expected 8 bytes ciphertext, got %d", len(ciphertext))
	}

	// Decrypt to verify round-trip
	block, _ := des.NewCipher(key[:])
	decrypted := make([]byte, 8)
	block.Decrypt(decrypted, ciphertext)

	if string(decrypted) != "hello123" {
		t.Errorf("round-trip failed: got %q, expected %q", decrypted, "hello123")
	}
}

// TestDESECBEncryptPadding verifies null-byte padding for non-aligned input.
func TestDESECBEncryptPadding(t *testing.T) {
	key := testConfig.DESKey
	plaintext := []byte("hello") // 5 bytes, should be padded to 8

	ciphertext, err := iovationsnarego.DesECBEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("DesECBEncrypt failed: %v", err)
	}

	if len(ciphertext) != 8 {
		t.Fatalf("expected 8 bytes (padded), got %d", len(ciphertext))
	}

	// Decrypt and verify padding
	block, _ := des.NewCipher(key[:])
	decrypted := make([]byte, 8)
	block.Decrypt(decrypted, ciphertext)

	if string(decrypted[:5]) != "hello" {
		t.Errorf("decrypted content wrong: %q", decrypted[:5])
	}
	// Last 3 bytes should be null padding
	for i := 5; i < 8; i++ {
		if decrypted[i] != 0 {
			t.Errorf("padding byte %d should be 0x00, got 0x%02x", i, decrypted[i])
		}
	}
}

// TestParseUA verifies browser detection matches snare.js __if_d for Chrome/Windows.
func TestParseUA(t *testing.T) {
	tests := []struct {
		ua            string
		expectBrowser string
		expectVersion string
		expectOS      string
		expectJBRCM   string
	}{
		{
			ua:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			expectBrowser: "Chrome",
			expectVersion: "131.0.0.0",
			expectOS:      "Windows NT 10.0",
			expectJBRCM:   "Win64; x64; KHTML, like Gecko",
		},
		{
			ua:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
			expectBrowser: "Edge",
			expectVersion: "131.0.0.0",
			expectOS:      "Windows NT 10.0",
			expectJBRCM:   "Win64; x64; KHTML, like Gecko",
		},
		{
			ua:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			expectBrowser: "Chrome",
			expectVersion: "131.0.0.0",
			expectOS:      "Intel Mac OS X 10_15_7",
			expectJBRCM:   "KHTML, like Gecko",
		},
		{
			ua:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			expectBrowser: "Chrome",
			expectVersion: "131.0.0.0",
			expectOS:      "Linux x86_64",
			expectJBRCM:   "KHTML, like Gecko",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expectBrowser+"/"+tt.expectOS, func(t *testing.T) {
			browser, version, os, jbrcm := iovationsnarego.ParseUA(tt.ua)

			if browser != tt.expectBrowser {
				t.Errorf("browser: got %q, want %q", browser, tt.expectBrowser)
			}
			if version != tt.expectVersion {
				t.Errorf("version: got %q, want %q", version, tt.expectVersion)
			}
			if os != tt.expectOS {
				t.Errorf("os: got %q, want %q", os, tt.expectOS)
			}
			if jbrcm != tt.expectJBRCM {
				t.Errorf("jbrcm: got %q, want %q", jbrcm, tt.expectJBRCM)
			}
		})
	}
}

// TestEndToEndSerialization builds the full KV list with known values and verifies
// the serialized output matches what the JS script would produce.
// After running extract_browser_values.js in your browser, paste the serialized
// string here as expectedSerialized to verify Go matches the browser exactly.
func TestEndToEndSerialization(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	appVersion := "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	browser, version, os, jbrcm := iovationsnarego.ParseUA(ua)

	// Fixed JSTIME for deterministic comparison
	jstime := "2026/02/07 12:00:00"

	kvs := []iovationsnarego.KVPair{
		// Init phase (set during snare.js startup)
		{Key: "FLRTD", Value: testConfig.Token},
		{Key: "INTLOC", Value: "https://webservices.global-e.com/Checkout/v2/8u22/test"},
		{Key: "JINT", Value: "form"},
		// Data collection phase
		{Key: "JENBL", Value: "1"},
		{Key: "JSSRC", Value: testConfig.JSSRC},
		{Key: "UAGT", Value: ua},
		// JDIFF + SUAGT (UA differs from baked-in Edge UA, so always present for Chrome)
		{Key: "JDIFF", Value: "1"},
		{Key: "SUAGT", Value: testConfig.SUAGT},
		{Key: "HACCLNG", Value: testConfig.HACCLNG},
		// HACCCHR skipped — undefined in modern Chrome, __if_fc skips it
		{Key: "JSVER", Value: testConfig.JSVER},
		{Key: "TZON", Value: "-60"},
		{Key: "JSTIME", Value: jstime},
		{Key: "SVRTIME", Value: testConfig.SVRTIME},
		{Key: "JBRNM", Value: browser},
		{Key: "JBRVR", Value: version},
		{Key: "JBROS", Value: os},
		{Key: "BBOUT", Value: testConfig.BBOUT},
		{Key: "APVER", Value: appVersion},
		{Key: "APNAM", Value: "Netscape"},
		{Key: "NPLAT", Value: "Win32"},
		{Key: "JBRCM", Value: jbrcm},
		{Key: "JLANG", Value: "en-US"},
		// JCOX skipped — cookies enabled, __if_fc skips empty values
		{Key: "IGGY", Value: testConfig.IGGY},
		{Key: "JRES", Value: "1440x2560"},
		// JSMBR, XREQW skipped — empty on desktop, __if_fc skips them
		{Key: "JPLGNS", Value: "internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;"},
		// JREFRR skipped — no referrer, __if_fc skips empty values
	}

	serialized := iovationsnarego.SerializeKVs(kvs)

	// Verify structure
	t.Logf("Serialized length: %d chars", len(serialized))
	t.Logf("Serialized (first 200): %.200s...", serialized)

	// Verify count prefix
	countHex := serialized[:4]
	expectedCount := fmt.Sprintf("%04x", len(kvs))
	if countHex != expectedCount {
		t.Errorf("count prefix: got %s, want %s", countHex, expectedCount)
	}

	// Verify first field is FLRTD (init phase comes first)
	if !strings.HasPrefix(serialized[4:], "0005FLRTD") {
		t.Errorf("first field should be FLRTD, got: %.20s", serialized[4:])
	}

	// Encrypt and verify output format
	ciphertext, err := iovationsnarego.DesECBEncrypt(testConfig.DESKey, []byte(serialized))
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	blackbox := "0400" + base64.StdEncoding.EncodeToString(ciphertext)

	t.Logf("Blackbox length: %d chars", len(blackbox))
	t.Logf("Blackbox: %s", blackbox)

	// Verify format
	if !strings.HasPrefix(blackbox, "0400") {
		t.Error("blackbox should start with 0400")
	}
	if len(blackbox) < 400 || len(blackbox) > 2000 {
		t.Errorf("blackbox length %d outside expected range 400-2000", len(blackbox))
	}

	// Verify we can decrypt back
	decoded, err := base64.StdEncoding.DecodeString(blackbox[4:])
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	block, _ := des.NewCipher(testConfig.DESKey[:])
	decrypted := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i += 8 {
		block.Decrypt(decrypted[i:i+8], decoded[i:i+8])
	}

	decryptedStr := strings.TrimRight(string(decrypted), "\x00")
	if decryptedStr != serialized {
		t.Errorf("round-trip mismatch:\n  decrypted: %.100s...\n  original:  %.100s...", decryptedStr, serialized)
	}
}

// TestEndToEndGenerate verifies the full Generate() pipeline produces valid output.
func TestEndToEndGenerate(t *testing.T) {
	gen, err := iovationsnarego.NewBlackboxGenerator(testConfig, true, true)
	if err != nil {
		t.Fatalf("NewBlackboxGenerator failed: %v", err)
	}

	params := &iovationsnarego.BlackboxParams{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		PageURL:         "https://webservices.global-e.com/Checkout/v2/8u22/test?foo=bar",
		Referer:         "",
		TimezoneOffset:  -60,
		Language:        "en-US",
		Platform:        "Win32",
		IntegrationType: iovationsnarego.Form,
	}

	bb := gen.Generate(params)

	t.Logf("Generated blackbox: %s", bb)
	t.Logf("Length: %d", len(bb))

	// Basic format checks
	if !strings.HasPrefix(bb, "0400") {
		t.Error("should start with 0400 version prefix")
	}
	if len(bb) < 400 || len(bb) > 2000 {
		t.Errorf("length %d outside expected range 400-2000", len(bb))
	}

	// Verify the base64 payload is valid
	_, err = base64.StdEncoding.DecodeString(bb[4:])
	if err != nil {
		t.Errorf("invalid base64 payload: %v", err)
	}

	// Generate a second one — may be identical if called within the same second
	// (JSTIME has 1-second granularity and resolution pool may be small).
	// This is expected behavior: uniqueness comes from per-call JSTIME variance over time.
	bb2 := gen.Generate(params)
	if bb == bb2 {
		t.Log("two consecutive same-second Generate() calls produced identical output (expected with small resolution pool)")
	} else {
		t.Log("two consecutive Generate() calls produced different output")
	}

	// Decrypt and verify key fields are present
	decoded, _ := base64.StdEncoding.DecodeString(bb[4:])
	block, _ := des.NewCipher(testConfig.DESKey[:])
	decrypted := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i += 8 {
		block.Decrypt(decrypted[i:i+8], decoded[i:i+8])
	}
	plaintext := string(decrypted)

	expectedFields := []string{"JENBL", "JSSRC", "UAGT", "FLRTD", "JDIFF", "SUAGT",
		"HACCLNG", "JSVER", "TZON", "JSTIME", "SVRTIME",
		"JBRNM", "JBRVR", "JBROS", "BBOUT", "APVER", "APNAM", "NPLAT",
		"JBRCM", "JLANG", "IGGY", "JRES",
		"JPLGNS", "JINT", "INTLOC"}

	for _, field := range expectedFields {
		if !strings.Contains(plaintext, field) {
			t.Errorf("decrypted blackbox missing field: %s", field)
		}
	}

	// Verify specific values in decrypted payload
	if !strings.Contains(plaintext, "Chrome") {
		t.Error("decrypted blackbox should contain 'Chrome' as JBRNM")
	}
	if !strings.Contains(plaintext, "Windows NT 10.0") {
		t.Error("decrypted blackbox should contain 'Windows NT 10.0' as JBROS")
	}
	if !strings.Contains(plaintext, testConfig.IGGY) {
		t.Error("decrypted blackbox should contain IGGY value")
	}
	if !strings.Contains(plaintext, "Win64; x64; KHTML, like Gecko") {
		t.Error("decrypted blackbox should contain JBRCM value")
	}
	// Verify query params were stripped from INTLOC
	if strings.Contains(plaintext, "foo=bar") {
		t.Error("INTLOC should not contain query params")
	}
	if !strings.Contains(plaintext, "https://webservices.global-e.com/Checkout/v2/8u22/test") {
		t.Error("decrypted blackbox should contain page URL without query params")
	}
}

// TestBrowserUADetection verifies our Go UA parsing matches what the browser's JS script detected
// for Chrome 144 on Windows. Values from extract_browser_values.js run on pokemoncenter.com/en-de/intl-checkout.
func TestBrowserUADetection(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"

	browser, version, osName, jbrcm := iovationsnarego.ParseUA(ua)

	if browser != "Chrome" {
		t.Errorf("browser: got %q, want %q", browser, "Chrome")
	}
	if version != "144.0.0.0" {
		t.Errorf("version: got %q, want %q", version, "144.0.0.0")
	}
	if osName != "Windows NT 10.0" {
		t.Errorf("os: got %q, want %q", osName, "Windows NT 10.0")
	}
	if jbrcm != "Win64; x64; KHTML, like Gecko" {
		t.Errorf("jbrcm: got %q, want %q", jbrcm, "Win64; x64; KHTML, like Gecko")
	}
}

// TestBrowserSerializationMatch verifies our Go serialization matches the browser's JS serialization
// character-for-character. This test uses the exact browser values (including JS placeholder strings
// for snare.js internals that weren't loaded) to prove the serialization algorithm is identical.
// Values from extract_browser_values.js run on pokemoncenter.com/en-de/intl-checkout.
func TestBrowserSerializationMatch(t *testing.T) {
	// Exact serialized output from the browser's JS script
	expectedSerialized := "001c0005JENBL000110005JSSRC002e(paste from ParseSnareJS or _i_cr._i_gi.JSSRC)0004UAGT006fMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.360007JSTOKEN0019(paste from ParseSnareJS)0007HACCLNG00000007HACCCHR00000005JSVER00000004TZON0003-600006JSTIME00132026/02/07 00:16:400007SVRTIME00000005JBRNM0006Chrome0005JBRVR0009144.0.0.00005JBROS000fWindows NT 10.00005BBOUT000aioBlackBox0005APVER00675.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.360005APNAM0008Netscape0005NPLAT0005Win320005JBRCM001dWin64; x64; KHTML, like Gecko0005JLANG0005pl-PL0004JCOX00000004IGGY00000004JRES00091440x25600005JSMBR00000005XREQW00000006JPLGNS0064internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;0006JREFRR00000004JINT0004form0006INTLOC0031https://www.pokemoncenter.com/en-de/intl-checkout"

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
	browser, version, osName, jbrcm := iovationsnarego.ParseUA(ua)

	appVersion := "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"

	// Use the exact same values the JS script used (including placeholder strings for snare.js internals
	// that weren't loaded — snare.js wasn't present on the page so _i_cr._i_gi was empty)
	kvs := []iovationsnarego.KVPair{
		{Key: "JENBL", Value: "1"},
		{Key: "JSSRC", Value: "(paste from ParseSnareJS or _i_cr._i_gi.JSSRC)"},
		{Key: "UAGT", Value: ua},
		{Key: "JSTOKEN", Value: "(paste from ParseSnareJS)"},
		// No JDIFF/SUAGT — snare.js wasn't loaded, so no baked-in UA to compare against
		{Key: "HACCLNG", Value: ""},
		{Key: "HACCCHR", Value: ""},
		{Key: "JSVER", Value: ""},
		{Key: "TZON", Value: "-60"},
		{Key: "JSTIME", Value: "2026/02/07 00:16:40"},
		{Key: "SVRTIME", Value: ""},
		{Key: "JBRNM", Value: browser},
		{Key: "JBRVR", Value: version},
		{Key: "JBROS", Value: osName},
		{Key: "BBOUT", Value: "ioBlackBox"},
		{Key: "APVER", Value: appVersion},
		{Key: "APNAM", Value: "Netscape"},
		{Key: "NPLAT", Value: "Win32"},
		{Key: "JBRCM", Value: jbrcm},
		{Key: "JLANG", Value: "pl-PL"},
		{Key: "JCOX", Value: ""},
		{Key: "IGGY", Value: ""},
		{Key: "JRES", Value: "1440x2560"},
		{Key: "JSMBR", Value: ""},
		{Key: "XREQW", Value: ""},
		{Key: "JPLGNS", Value: "internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;"},
		{Key: "JREFRR", Value: ""},
		{Key: "JINT", Value: "form"},
		{Key: "INTLOC", Value: "https://www.pokemoncenter.com/en-de/intl-checkout"},
	}

	serialized := iovationsnarego.SerializeKVs(kvs)

	if serialized != expectedSerialized {
		t.Errorf("serialized mismatch (lengths: go=%d, js=%d)", len(serialized), len(expectedSerialized))
		// Find first difference
		minLen := len(serialized)
		if len(expectedSerialized) < minLen {
			minLen = len(expectedSerialized)
		}
		for i := 0; i < minLen; i++ {
			if serialized[i] != expectedSerialized[i] {
				t.Errorf("first diff at position %d: go=%c js=%c", i, serialized[i], expectedSerialized[i])
				t.Errorf("  go context: ...%s...", serialized[max(0, i-20):min(len(serialized), i+20)])
				t.Errorf("  js context: ...%s...", expectedSerialized[max(0, i-20):min(len(expectedSerialized), i+20)])
				break
			}
		}
	} else {
		t.Logf("Go serialization matches browser JS output exactly (%d chars)", len(serialized))
	}
}

// TestActualBlackboxMatch decrypts actual blackboxes produced by snare.js in the browser,
// rebuilds them using our Go serialization + DES-ECB encryption, and verifies byte-identical output.
// Captured from pokemoncenter.com/en-de GlobalE checkout page, Chrome 144, 2026-02-07.
func TestActualBlackboxMatch(t *testing.T) {
	tests := []struct {
		name           string
		jstime         string
		actualBlackbox string
	}{
		{
			name:           "capture1_00:22:48",
			jstime:         "2026/02/07 00:22:48",
			actualBlackbox: "0400Ia/vP4SUWbEXk1Rjuv1iJgWxIe7xNABi4fWLoKuCjDO1I7X1XkVbR56yHWIulRE2G351wfp+MZWAa+qm7VSS+5sZhQDshHSv/H4ocE4MzX7znyLr74B0cp4eYE6KbXMUVXuR1VKxnE7cmENPgFxuVhapolaJgpsfz9PMT+sd4Hssi2Om6MjHILegtlGVZwzH8t5CZB4va9TvxphxpGRDC1ubY/nybMNZCM87zpQVIfakU2g45lE5duixLXGBICA18sQyiQagYnGC7XLTgcuc7M6mhllQ7/XHYDvethm0ixXKgDzSlcJpdgaIbEN+Is0U0LVQmADUFBlDgm50c6V/UpKetslI3IixYH1H5YVrp93GJ/KtOFGi8RKePA1UZdKAZDwic+y5/r+SkyAbziDM7k8xAXTS4l7D1erHMnjL6ri69/6OW8z8/eB4gTqSk7BNTMj6Y82LrlflYU9iUMb03WGA1qU96BMIDClysds/e/lhQXwEoP1IufHBQm916StC15tFwbb5NkVtrNHzt95ePgXs+oQQc60trrGto44dFZ/k0B48ux+V4SxwhwBmNydI6S6la0lc7CNSwejOX5dhKDBAKBIrRLbRVKNQ0ZFLTxjZjVp/OGcTE7pTFHEEYpnCeFUoW2PhFQTWYv9wDTbcbtL6kDvPLtrAjahWxfFQty48VzQuNHJwLtoEE4UmBo61KxTQupUrXZ6AgVfWd/zGnQ9yZLQFQqt8324pPvx9L1sHYYNdyOmCGb2SVUU7DsShjNXsgMEghG04JacwCaWoKvPoP5g1QwsR016MDWI9FIwakOpRyDJRTXQmCfypPXFCYTtUNo5lYHzXGwJTIPPVuFJdhWjQw/rtkhg+Vl9yih8mlBgAVSsOV9IpG/94dXdCJuhcu7D0uboRqSsRkc8t5nZxk/30Im3yRw6NL2GAwt9rATguwW95O22s0fO33l4+TSvNeefkn5z6DLgVREB6faGKC5f/uuA0fASXqv3joTzrfsVTizBAlNebRcG2+TZFbazR87feXj4F7PqEEHOtLa6xraOOHRWf5NAePLsfleEscIcAZjcnSOkupWtJXOwjUsHozl+XYSgwQCgSK0S20VSjUNGRS08YmsBHeg28bwmRO+WoF0LXY+ZjVekMYG3JYXyFHBbsmyyzb0vSwWRA+eSMeWgCk0M8kgQVobtOy5kXbeVOAqXsCI9qpLt2ZL85ADPXWwUTnjUH20A9afihHFeovP7W+WpQCv10TaNx+XQgqHxyPWh5invzeyaYvXzwFBJ/UmWA7iYoXqWkOrG7Oay0CfZBfAt/rYlxWfdZmH81YmMYi0T6kqHW8wK2R6H4yXKQSqRQOww3A8cSqM9ecGoFOMLIiHgNeAsns9uUMqznVb7uHgXQGZLoweg2L6UyClmaO3JEWMfkTEmWwQPJZ5nCGPGKh21isC2ODMcwYCQtMuQQ3gvsR8jwjs5Ca2/wBdhim9vK/UsQ5XOYm0OqKbAtjgzHMGAkLTLkEN4L7EfI8I7OQmtv8AXYYpvbyv1LEOVzmJtDqimwLY4MxzBgJAzpFXhXpEZv",
		},
		{
			name:           "capture2_00:38:33",
			jstime:         "2026/02/07 00:38:33",
			actualBlackbox: "0400Ia/vP4SUWbEXk1Rjuv1iJgWxIe7xNABi4fWLoKuCjDO1I7X1XkVbR56yHWIulRE2G351wfp+MZWAa+qm7VSS+5sZhQDshHSv/H4ocE4MzX7znyLr74B0cp4eYE6KbXMUVXuR1VKxnE7cmENPgFxuVhapolaJgpsfz9PMT+sd4Hssi2Om6MjHILegtlGVZwzH8t5CZB4va9TvxphxpGRDC1ubY/nybMNZCM87zpQVIfakU2g45lE5duixLXGBICA18sQyiQagYnGC7XLTgcuc7M6mhllQ7/XHYDvethm0ixXKgDzSlcJpdgaIbEN+Is0U0LVQmADUFBlDgm50c6V/UpKetslI3IixYH1H5YVrp93GJ/KtOFGi8RKePA1UZdKAZDwic+y5/r+SkyAbziDM7k8xAXTS4l7D1erHMnjL6ri69/6OW8z8/eB4gTqSk7BNTMj6Y82LrlflYU9iUMb03WGA1qU96BMIDClysds/e/lhQXwEoP1IufHBQm916StC15tFwbb5NkVtrNHzt95ePgXs+oQQc60trrGto44dFZ/k0B48ux+V4SxwhwBmNydI6S6la0lc7CNSwejOX5dhKDBAKBIrRLbRVKNQ0ZFLTxjZjVp/OGcTE7pTFHEEYpnCeFUoW2PhFQTWYv9wDTbcbtL6kDvPLtrAjahWxfFQty48VzQuNHJwLtoEE4UmBo61KxTQupUrXZ6AgVfWd/zGnQ9yZLQFQqt8324pPvx9L1sHYYNdyOmCGb2SVUU7DsShjNXsgMEghG04JacwCaWoKvPoP5g1QwsR016MDWI9FIwakOpRyDJRTUD+16TB1TvXYTtUNo5lYHzXGwJTIPPVuFJdhWjQw/rtkhg+Vl9yih8mlBgAVSsOV9IpG/94dXdCJuhcu7D0uboRqSsRkc8t5nZxk/30Im3yRw6NL2GAwt9rATguwW95O22s0fO33l4+TSvNeefkn5z6DLgVREB6faGKC5f/uuA0fASXqv3joTzrfsVTizBAlNebRcG2+TZFbazR87feXj4F7PqEEHOtLa6xraOOHRWf5NAePLsfleEscIcAZjcnSOkupWtJXOwjUsHozl+XYSgwQCgSK0S20VSjUNGRS08YmsBHeg28bwmRO+WoF0LXY+ZjVekMYG3JYXyFHBbsmyyzb0vSwWRA+eSMeWgCk0M8kgQVobtOy5kXbeVOAqXsCI9qpLt2ZL85ADPXWwUTnjUH20A9afihHFeovP7W+WpQCv10TaNx+XQgqHxyPWh5invzeyaYvXzwFBJ/UmWA7iYoXqWkOrG7Oay0CfZBfAt/rYlxWfdZmH81YmMYi0T6kqHW8wK2R6H4yXKQSqRQOww3A8cSqM9ecGoFOMLIiHgNeAsns9uUMqznVb7uHgXQGZLoweg2L6UyClmaO3JEWMfkTEmWwQPJZ5nCGPGKh21isC2ODMcwYCQtMuQQ3gvsR8jwjs5Ca2/wBdhim9vK/UsQ5XOYm0OqKbAtjgzHMGAkLTLkEN4L7EfI8I7OQmtv8AXYYpvbyv1LEOVzmJtDqimwLY4MxzBgJAzpFXhXpEZv",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the KV list matching snare.js internal dictionary insertion order.
			// Init fields first, then data collection fields. Only non-empty values.
			kvs := []iovationsnarego.KVPair{
				// Init phase (set during snare.js startup)
				{Key: "FLRTD", Value: "/eYbIxrn3mAExmFkurAILblYjwPfFgzes7T1pLQbJMI="},
				{Key: "INTLOC", Value: "https://webservices.global-e.com/Checkout/v2/8u22/24ea5189-d0e9-4ded-9a65-a51f5b6fdd27"},
				{Key: "JINT", Value: "form"},
				// Data collection phase
				{Key: "JENBL", Value: "1"},
				{Key: "JSSRC", Value: "am1prwdp03.iovation.us"},
				{Key: "UAGT", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"},
				{Key: "JDIFF", Value: "1"},
				{Key: "SUAGT", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134"},
				{Key: "HACCLNG", Value: "en-IL,en-US;q=0.8,en;q=0.5,he;q=0.3"},
				{Key: "JSVER", Value: "3.1.3"},
				{Key: "TZON", Value: "-60"},
				{Key: "JSTIME", Value: tt.jstime},
				{Key: "SVRTIME", Value: "2018/11/28 11:57:02"},
				{Key: "JBRNM", Value: "Chrome"},
				{Key: "JBRVR", Value: "144.0.0.0"},
				{Key: "JBROS", Value: "Windows NT 10.0"},
				{Key: "BBOUT", Value: "ioBlackBox"},
				{Key: "APVER", Value: "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"},
				{Key: "APNAM", Value: "Netscape"},
				{Key: "NPLAT", Value: "Win32"},
				{Key: "JBRCM", Value: "Win64; x64; KHTML, like Gecko"},
				{Key: "JLANG", Value: "pl-PL"},
				{Key: "IGGY", Value: "ajhX8U8YHxOyzdXEDGbRRazTg5OktIgQ4lN3PpeFbdPcPWTmwbnv9GX54KydaIMo"},
				{Key: "JRES", Value: "1440x2560"},
				{Key: "JPLGNS", Value: "internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;internal-pdf-viewer;"},
			}

			// Serialize
			serialized := iovationsnarego.SerializeKVs(kvs)

			// Encrypt
			ciphertext, err := iovationsnarego.DesECBEncrypt(testConfig.DESKey, []byte(serialized))
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}
			goBlackbox := "0400" + base64.StdEncoding.EncodeToString(ciphertext)

			if goBlackbox == tt.actualBlackbox {
				t.Logf("FULL MATCH: Go blackbox matches actual snare.js blackbox (%d chars)", len(goBlackbox))
			} else {
				t.Errorf("blackbox mismatch (lengths: go=%d, actual=%d)", len(goBlackbox), len(tt.actualBlackbox))
				// Decrypt actual to find the difference
				decoded, _ := base64.StdEncoding.DecodeString(tt.actualBlackbox[4:])
				block, _ := des.NewCipher(testConfig.DESKey[:])
				decrypted := make([]byte, len(decoded))
				for i := 0; i < len(decoded); i += 8 {
					block.Decrypt(decrypted[i:i+8], decoded[i:i+8])
				}
				actualPlaintext := strings.TrimRight(string(decrypted), "\x00")
				t.Errorf("  go plaintext len:     %d", len(serialized))
				t.Errorf("  actual plaintext len: %d", len(actualPlaintext))
				// Find first diff
				minLen := len(serialized)
				if len(actualPlaintext) < minLen {
					minLen = len(actualPlaintext)
				}
				for i := 0; i < minLen; i++ {
					if serialized[i] != actualPlaintext[i] {
						start := max(0, i-20)
						t.Errorf("  first diff at pos %d: go='%c' actual='%c'", i, serialized[i], actualPlaintext[i])
						t.Errorf("  go ctx:     ...%s...", serialized[start:min(len(serialized), i+20)])
						t.Errorf("  actual ctx: ...%s...", actualPlaintext[start:min(len(actualPlaintext), i+20)])
						break
					}
				}
			}
		})
	}
}
