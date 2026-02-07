package iovationsnarego

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

const maxSerializedSize = 4000

var browserNameRegex = regexp.MustCompile(`(?:Chrome|Firefox|Safari|Edge|Opera|OPR|MSIE|Trident)`)
var chromeVersionRegex = regexp.MustCompile(`Chrome/(\d+[\d.]*)`)
var firefoxVersionRegex = regexp.MustCompile(`Firefox/(\d+[\d.]*)`)
var edgeVersionRegex = regexp.MustCompile(`Edg(?:e)?/(\d+[\d.]*)`)
var parenGroupRegex = regexp.MustCompile(`\([^)]*\)`)

// osPatterns matches the snare.js __if_jk OS detection priority list.
// Index 0 ("Linux") doesn't return early — continues searching for a more specific match.
var osPatterns = []string{
	"Linux", "Windows Phone", "Android", "BSD", "Ubuntu", "Irix", "MIDP",
	"Windows ", "Mac OS X", "Debian", "Mac", "Playstation", "Wii", "Xbox",
	"Win9", "BlackBerry", "WinNT", "iPhone", "iPad", "OS",
}

var resolutions = []*Resolution{
	{
		Width:  2560,
		Height: 1440,
	},
}

// SerializeKVs serializes key-value pairs into the snare.js hex-length-prefixed format.
// Format: hex4(count) + [hex4(keyLen) + UPPER(key) + hex4(valLen) + value]*N
func SerializeKVs(kvs []KVPair) string {
	var sb strings.Builder
	count := len(kvs)
	sb.WriteString(fmt.Sprintf("%04x", count))

	totalLen := 4 // count prefix
	for _, kv := range kvs {
		key := strings.ToUpper(kv.Key)
		val := kv.Value

		entryLen := 4 + len(key) + 4 + len(val)
		if totalLen+entryLen > maxSerializedSize {
			break
		}

		sb.WriteString(fmt.Sprintf("%04x", len(key)))
		sb.WriteString(key)
		sb.WriteString(fmt.Sprintf("%04x", len(val)))
		sb.WriteString(val)
		totalLen += entryLen
	}

	return sb.String()
}

// DesECBEncrypt encrypts data using single DES in ECB mode with null-byte padding.
func DesECBEncrypt(key [8]byte, plaintext []byte) ([]byte, error) {
	block, err := des.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	// Pad to 8-byte boundary with null bytes
	blockSize := block.BlockSize()
	padLen := blockSize - (len(plaintext) % blockSize)
	if padLen != blockSize {
		plaintext = append(plaintext, make([]byte, padLen)...)
	}

	ciphertext := make([]byte, len(plaintext))
	ecb := newECBEncrypter(block)
	ecb.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// ParseUA extracts browser name, version, OS, and browser comment from a User-Agent string.
// Matches the snare.js __if_d() browser detection constructor.
func ParseUA(ua string) (browserName, browserVersion, osName, jbrcm string) {
	// Browser name and version
	if m := chromeVersionRegex.FindStringSubmatch(ua); len(m) == 2 {
		// Check if it's actually Edge
		if em := edgeVersionRegex.FindStringSubmatch(ua); len(em) == 2 {
			browserName = "Edge"
			browserVersion = em[1]
		} else {
			browserName = "Chrome"
			browserVersion = m[1]
		}
	} else if m := firefoxVersionRegex.FindStringSubmatch(ua); len(m) == 2 {
		browserName = "Firefox"
		browserVersion = m[1]
	} else if m := edgeVersionRegex.FindStringSubmatch(ua); len(m) == 2 {
		browserName = "Edge"
		browserVersion = m[1]
	} else if browserNameRegex.MatchString(ua) {
		browserName = browserNameRegex.FindString(ua)
		browserVersion = ""
	} else {
		browserName = "Unknown"
		browserVersion = ""
	}

	// Extract attributes from parenthetical groups (snare.js __if_hn)
	attributes := extractUAAttributes(ua)

	// OS detection from attributes (snare.js __if_jk)
	osName = detectOS(attributes)

	// JBRCM: attributes joined with "; ", everything after the OS token stripped
	jbrcm = buildJBRCM(attributes, osName)

	return
}

// extractUAAttributes extracts tokens from all parenthetical groups in the UA string.
// Matches snare.js __if_hn: splits each (...) group by ";", trims whitespace.
func extractUAAttributes(ua string) []string {
	groups := parenGroupRegex.FindAllString(ua, -1)
	var attributes []string
	for _, group := range groups {
		group = strings.Trim(group, "()")
		tokens := strings.Split(group, ";")
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			if token != "" {
				attributes = append(attributes, token)
			}
		}
	}
	return attributes
}

// detectOS finds the OS name from UA attributes using the snare.js priority list.
// Falls back to "Win32" (navigator.platform default) if no match.
func detectOS(attributes []string) string {
	os := "Win32"
	for i, pattern := range osPatterns {
		for _, attr := range attributes {
			if strings.Contains(strings.ToUpper(attr), strings.ToUpper(pattern)) {
				os = attr
				if i > 0 {
					return os
				}
			}
		}
	}
	return os
}

// buildJBRCM builds the browser comment field from UA attributes.
// Joins all attributes with "; ", then strips everything up to and including the OS token.
func buildJBRCM(attributes []string, osName string) string {
	if len(attributes) == 0 {
		return ""
	}
	joined := strings.Join(attributes, "; ")
	re := regexp.MustCompile(`^.*` + regexp.QuoteMeta(osName) + `;? ?`)
	result := re.ReplaceAllString(joined, "")
	return result
}

// base64Encode returns the standard base64 encoding of data.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// KVPair is an ordered key-value pair for serialization.
type KVPair struct {
	Key   string
	Value string
}

// ECB mode implementation (Go stdlib doesn't include ECB)
type ecbEncrypter struct {
	b         cipher.Block
	blockSize int
}

func newECBEncrypter(b cipher.Block) *ecbEncrypter {
	return &ecbEncrypter{b: b, blockSize: b.BlockSize()}
}

func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	for len(src) > 0 {
		e.b.Encrypt(dst[:e.blockSize], src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}
