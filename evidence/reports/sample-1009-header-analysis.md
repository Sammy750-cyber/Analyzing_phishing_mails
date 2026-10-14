# Case ID-PH002 Header Analysis Report  
**Sample file:** `sample-1009.eml`  
**Header Path:** [Header output.json](../headers/sample-1009-analysis.json) 

**Sample SHA256:** `688d5eb7429d8fc5c529f60872d855e79562ad9f06db924d536b31e21e7b22f8`  
**Analysis date:** 2026-10-14  
**Verdict:** **Likely phishing / brand impersonation.** Authentication passes only because the message was sent from a legitimate Gmail account, not because it is a legitimate bank communication.

---

## 1. Executive Summary

The header was from the sample uusing the `script/analyse_header.py`

```bash
python .\script\analyze_headers.py .\samples\sample-1009.eml --output .\evidence\headers\sample-1009-analysis.json
```

This email appears to be a Portuguese-language phishing lure impersonating **“BB”**, likely **Banco do Brasil**, with the subject **“Crédito IR Liberado”** (“Income Tax credit released”). The display name claims to be a customer communication from BB, but the actual sender address is a free Gmail account:

`sel553r@gmail.com`

SPF, DKIM, and DMARC all pass, but they validate **gmail.com**, not Banco do Brasil. This is a common pattern: attackers use free webmail accounts so authentication passes, while relying on the display name and message content to deceive recipients.

The message includes a suspicious PDF attachment and was delivered to `phishing@pot`, indicating this is likely a phishing sample or sinkhole message.

**Risk:** High likelihood of phishing.  
**Header-level spoofing:** Not detected.  
**Brand/display-name spoofing:** Strongly suspected.

---

## 2. Key Metadata

| Field | Value |
|---|---|
| From | `"[BB] - Comunicado ao cliente - Cod.  3391350884491727" <sel553r@gmail.com>` |
| To | `phishing@pot` |
| Return-Path | `sel553r@gmail.com` |
| Subject | `Crédito IR Liberado - v5V0ZVRe1HjazliqQoYz` |
| Date | `Sat, 29 Jul 2023 18:08:24 +0000` |
| Message-ID | `<d21e5a021950b9fdf1aab7fa0c059612@gmail.com>` |
| Attachment | `U1vn48GmdQr.pdf` |
| Attachment type | `application/pdf` |
| Attachment size | `99,717 bytes` |
| Attachment SHA256 | `831b3c4cfe0ff181e09a584d180d4ff5b9963a1e7be5e25d6b857ad63713d024` |

---

## 3. Authentication Analysis

| Check | Result | Notes |
|---|---|---|
| SPF | Pass | Sender IP `209.85.222.173` is permitted for `gmail.com` |
| DKIM | Pass | `header.d=gmail.com` |
| DMARC | Pass | `header.from=gmail.com` |
| Microsoft compauth | Pass | `reason=100` |

### Important caveat
These authentication results only prove that the message was sent through Google/Gmail infrastructure and that the visible From domain is `gmail.com`. They do **not** prove that the sender is Banco do Brasil, nor that the attachment or message content is legitimate.

The From domain and Return-Path both use `gmail.com`, so SPF/DKIM/DMARC alignment passes. This is expected for a Gmail-originated message. It does not validate the “BB” display name.

---

## 4. Routing and Origin Analysis

The received chain shows the message originated from a client connecting to Gmail’s authenticated SMTP service:

1. `c3.domain [20.161.8.184]` → `smtp.gmail.com` via **ESMTPSA**  
   - `ESMTPSA` means authenticated SMTP submission over TLS.
   - This indicates the sender authenticated to Gmail using an account or app password.

2. `mail-qk1-f173.google.com [209.85.222.173]` → Microsoft Outlook  
   - This is Google’s outbound sending infrastructure.

3. Microsoft 365 internal routing:
   - `BN1NAM02FT009` → `BN9PR03CA0616` → `PH7PR19MB5487` → `MN0PR19MB6312`

### Origin IP
- **Client/origin IP:** `20.161.8.184`
- **Hostname claimed:** `c3.domain`
- This IP is not the Google sending IP. It is the system that authenticated to Gmail. It may be a proxy, VPN, cloud host, or compromised endpoint. It should be investigated if this appears in a real environment.

### Timing
The Date header and Received timestamps are consistent:
- Date: `18:08:24 +0000`
- Gmail submission: `11:08:26 -0700` = `18:08:26 UTC`
- Outlook receipt: `18:08:27 UTC`

No obvious time-zone or timestamp anomaly.

---

## 5. Phishing / Suspicious Indicators

1. **Brand impersonation in display name**  
   The display name begins with `[BB] - Comunicado ao cliente`, which strongly suggests Banco do Brasil. The actual domain is `gmail.com`.

2. **Free webmail sender**  
   Legitimate banks rarely send customer communications from `@gmail.com`.

3. **Tax-credit lure**  
   Subject: `Crédito IR Liberado` — “Income Tax credit released.” This is a common financial phishing theme in Brazil.

4. **Randomized subject token**  
   `v5V0ZVRe1HjazliqQoYz` appears to be a random tracking or anti-filter token.

5. **Randomized attachment filename**  
   `U1vn48GmdQr.pdf` is not a normal bank document name and may be used to evade hash/signature detection.

6. **No bank domain anywhere in headers**  
   The From, Return-Path, Message-ID, and DKIM domain are all `gmail.com`. There is no `bb.com.br` or Banco do Brasil domain.

7. **Recipient is a phishing sinkhole**  
   `To: phishing@pot` suggests this message was sent to a phishing report mailbox or test sink, not a real customer.

8. **Authenticated Gmail submission from a non-Google origin**  
   The origin client `c3.domain [20.161.8.184]` authenticated to Gmail. This can indicate a compromised mailbox, attacker-controlled Gmail account, or automated phishing tool.

---

## 6. Attachment Assessment

| Property | Value |
|---|---|
| Filename | `U1vn48GmdQr.pdf` |
| Content type | `application/pdf` |
| Size | `99,717 bytes` |
| SHA256 | `831b3c4cfe0ff181e09a584d180d4ff5b9963a1e7be5e25d6b857ad63713d024` |

The PDF was **not executed or opened** during this analysis. It should be detonated in a sandbox. Typical phishing PDFs may contain:
- Embedded URLs
- QR codes
- Fake bank login pages
- Malicious JavaScript
- Redirect instructions

---

## 7. Verdict

**Likely phishing.**  
The message uses a legitimate Gmail account to pass authentication, but impersonates Banco do Brasil via the display name and uses a tax-credit lure with a suspicious PDF attachment. Header authentication does not support legitimacy; it only confirms the message came through Gmail.

**Confidence:** High for phishing/brand impersonation based on headers and metadata.  
**Confidence in attachment maliciousness:** Unknown without sandboxing.

---

## 8. Recommended Actions

1. **Quarantine or block** messages matching:
   - Sender: `sel553r@gmail.com`
   - Display name containing `[BB] - Comunicado ao cliente`
   - Subject pattern: `Crédito IR Liberado`
   - Attachment hash: `831b3c4cfe0ff181e09a584d180d4ff5b9963a1e7be5e25d6b857ad63713d024`

2. **Search mail logs** for other messages from this sender, subject, or attachment hash.

3. **Sandbox the PDF** and extract any URLs, QR codes, or embedded files.

4. **Report the Gmail account** to Google as abuse/phishing.

5. **User awareness reminder:** SPF/DKIM/DMARC pass on Gmail does not mean a bank message is legitimate. Always verify the actual domain.

6. **If any user interacted** with the attachment or submitted credentials, initiate password reset, MFA review, and endpoint investigation.

---

## 9. Indicators of Compromise

| Type | Indicator |
|---|---|
| Sender email | `sel553r@gmail.com` |
| Display name | `[BB] - Comunicado ao cliente - Cod.  3391350884491727` |
| Return-Path | `sel553r@gmail.com` |
| Message-ID | `<d21e5a021950b9fdf1aab7fa0c059612@gmail.com>` |
| Subject | `Crédito IR Liberado - v5V0ZVRe1HjazliqQoYz` |
| Origin client IP | `20.161.8.184` |
| Origin hostname | `c3.domain` |
| Google sending IP | `209.85.222.173` |
| Attachment filename | `U1vn48GmdQr.pdf` |
| Attachment SHA256 | `831b3c4cfe0ff181e09a584d180d4ff5b9963a1e7be5e25d6b857ad63713d024` |
| Sample SHA256 | `688d5eb7429d8fc5c529f60872d855e79562ad9f06db924d536b31e21e7b22f8` |

---