# Iovation Snare Fingerprint Generator

A research reconstruction in Go of **TransUnion iovation's `snare.js` device-fingerprinting pipeline**: data collection, serialization and encryption of the `ioBlackBox` payload.

The implementation mirrors `snare.js` end to end and produces a valid `ioBlackBox` string, generated entirely locally.

> **Disclaimer**
> This project is for educational and research purposes only and is not affiliated with TransUnion or iovation. You are responsible for complying with all applicable laws, merchant terms of service, and fraud prevention terms.

---

## Usage

Below is a basic example showing how to generate a blackbox fingerprint from a site's `snare.js` configuration.

```go
func TestGenerateBlackbox(t *testing.T) {
    // 1. Find snare.js URL in page HTML
    snareURL, err := iovationsnarego.FindSnareURL(checkoutPageHTML)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    // 2. Fetch snare.js and parse build-specific config
    config, err := iovationsnarego.ParseSnareJS(snareJSBody)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    // 3. Set BBOUT from the page HTML (not present in snare.js)
    // Extract from: var io_bbout_element_id = 'ioBlackBox';
    config.BBOUT = "ioBlackBox"

    // 4. Create generator
    gen, err := iovationsnarego.NewBlackboxGenerator(config, false, false)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    // 5. Generate blackbox
    blackbox := gen.Generate(&iovationsnarego.BlackboxParams{
        UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        PageURL:         "https://webservices.global-e.com/Checkout/v2/0000/cartId",
        Referer:         "",
        Language:        "en-US",
        Platform:        "Win32",
		Resolution:      &iovationsnarego.Resolution{Width:2560, Height:1440}, // optional, will use random res if not set
        TimezoneOffset:  300,
        IntegrationType: iovationsnarego.Form,
    })

    fmt.Printf("Blackbox: %s\n", blackbox)
    // Output: 0400eFj3Hp2K... (400-600 characters)
}
```

### Important notes

- `ParseSnareJS` extracts most build-specific constants directly from the JavaScript source.
- **`BBOUT` must be set separately** — it lives in the page HTML (`var io_bbout_element_id = '...'`), not in snare.js. Set `config.BBOUT` after calling `ParseSnareJS`.
- The fingerprint is generated entirely locally with **no network requests** to Iovation servers.

---

## Output Format

The returned value is a string in the following format:

```
"0400" + base64(DES_ECB(serialized_data, key))
```

Result is typically **400-600 characters** and begins with the version prefix `0400`.

---

## Snare.js Configuration

### What is it?

Each site's `snare.js` build contains unique hardcoded values that are baked in at build time. These values are extracted dynamically using `ParseSnareJS()` — no manual configuration is required.

| Value | Description | Extraction Method |
|-------|-------------|-------------------|
| `IGGY` | 64-char hex subscriber/merchant identifier | Direct regex from snare.js |
| `JSSRC` | CDN/server identifier for the deployment | Base64 decode from snare.js |
| `BBOUT` | `io_bbout_element_id` — the HTML element ID where snare.js writes the blackbox | Extracted from page HTML (`var io_bbout_element_id = '...'`), **not** from snare.js |
| `SVRTIME` | Server-side build timestamp | Direct regex from snare.js |
| `Token` | Real-time detection token (FLRTD or JSTOKEN) | Direct regex from snare.js |
| `SUAGT` | Expected User-Agent baked into the build | URL decode from snare.js |
| `HACCLNG` | Expected Accept-Language baked into the build | URL decode from snare.js |
| `JSVER` | snare.js SDK version (e.g. "3.1.3") | Direct regex from snare.js |
| `DES Key` | 8-byte DES-ECB encryption key | Hex parse from `String.fromCharCode()` in snare.js |

> **Note:** `BBOUT` is the only config value **not** extracted by `ParseSnareJS()`. It lives in the page HTML as `var io_bbout_element_id = 'ioBlackBox'` and must be set on the `SnareConfig` by the caller after parsing.

### Where to find snare.js

On sites that use iovation, `snare.js` is loaded via a script tag. Use `FindSnareURL()` to extract the URL from the page HTML:

```go
snareURL, err := iovationsnarego.FindSnareURL(checkoutPageHTML)
// e.g. "https://s3.global-e.com/snare.js"
```

---

## Full Flow Diagram

### High-level Flow

```
┌──────────────────┐
│       Page       │
│  (HTML source)   │
└────────┬─────────┘
         │
         ├─ 1. FindSnareURL()
         │     Extract snare.js script URL
         │
         ├─ 2. Extract BBOUT
         │     var io_bbout_element_id = '...'
         ▼
┌──────────────────┐
│    snare.js      │
│  (JavaScript)    │
└────────┬─────────┘
         │
         │ 3. ParseSnareJS()
         │    Extract build-specific config
         ▼
┌──────────────────┐
│   SnareConfig    │
│  IGGY, DES Key,  │
│  SVRTIME, BBOUT  │
└────────┬─────────┘
         │
         │ 4. NewBlackboxGenerator()
         ▼
┌──────────────────────────┐
│   BlackboxGenerator      │
│   + BlackboxParams       │
│   (UA, URL, TZ, etc.)   │
└────────┬─────────────────┘
         │
         │ 5. Generate()
         ▼
┌──────────────────────────┐
│   Data Collection        │
│   ~30 browser/device     │
│   properties collected   │
└────────┬─────────────────┘
         │
         │ 6. Serialize
         ▼
┌──────────────────────────┐
│   Hex-Length-Prefixed    │
│   Serialization Format   │
│   (max 4000 chars)       │
└────────┬─────────────────┘
         │
         │ 7. Encrypt
         ▼
┌──────────────────────────┐
│   DES-ECB Encryption     │
│   (8-byte key, no IV)    │
└────────┬─────────────────┘
         │
         │ 8. Encode
         ▼
┌──────────────────────────┐
│   "0400" + base64(...)   │
│   ioBlackBox fingerprint │
│   (400-600 chars)        │
└──────────────────────────┘
```

### Step-by-step Breakdown

1. **Find snare.js**
   - `FindSnareURL()` extracts the snare.js script URL from the page HTML using regex.

2. **Extract BBOUT**
   - The caller extracts `io_bbout_element_id` from the page HTML (e.g. `var io_bbout_element_id = 'ioBlackBox'`).
   - This is the HTML element ID where snare.js writes the blackbox value.
   - Set it on `SnareConfig.BBOUT` before creating the generator.

3. **Parse Configuration**
   - `ParseSnareJS()` extracts all build-specific constants (IGGY, DES key, SVRTIME, etc.) from the JavaScript source using regex patterns.

4. **Create Generator**
   - `NewBlackboxGenerator()` validates the config and initializes the generator with a random seed.

5. **Collect Browser Properties**
   - The generator collects ~30 browser/device properties: User-Agent, browser name/version, OS, platform, screen resolution, timezone, language, page URL, plugins, and more.
   - UA parsing matches snare.js internal detection logic (`__if_d()`, `__if_hn()`, `__if_jk()`).

6. **Serialize**
   - Key-value pairs are serialized in the snare.js hex-length-prefixed format:
     ```
     hex4(count) + [hex4(keyLen) + UPPER(key) + hex4(valLen) + value]*N
     ```
   - Maximum 4000 characters total.

7. **Encrypt**
   - Single DES in ECB mode (no IV).
   - 8-byte key extracted from `String.fromCharCode()` in snare.js.
   - Input padded with null bytes to 8-byte boundary.

8. **Encode**
   - Ciphertext is base64 encoded and prefixed with the version string `"0400"`.

---

## Integration Types

The `IntegrationType` field tells the blackbox how the script was integrated on the page:

| Type | Value | Description |
|------|-------|-------------|
| `Callback` | `"callback"` | Page registered `window.io_bb_callback` to receive the blackbox |
| `Form` | `"form"` | snare.js writes the blackbox into a hidden `<input>` element |
| `Function` | `"function"` | `ioGetBlackbox()` was called explicitly to retrieve the blackbox |

For GlobalE checkout flows (e.g. Pokemon Center DE/NZ/AU), the integration type is `Form`.

## Maintained by status403

iovationsnare-go is built and maintained by [status403](https://status403.com/?utm_source=github&utm_medium=referral&utm_campaign=iovationsnare-go), a software house specializing in reverse engineering and anti-bot protected targets. The method behind reconstructions like this one is written up in [Reverse Engineering Anti-Bot JavaScript: Deobfuscation and VM Analysis](https://status403.com/blog/reverse-engineering-antibot-javascript?utm_source=github&utm_medium=referral&utm_campaign=iovationsnare-go).
