# CASE-PH001 Header Analysis Report  
**Sample file:** `sample-1.eml`  
**Sample SHA256:** `35ef116a75e5e46e6859b49b60a23b4ddfe5f91d1368e0fc67a16df698cb96e0`  
**Header Output:** [output.json](../headers/sample-1-analysis.json)

**Analysis date:** 2026-10-14  
**Verdict:** **Phishing / brand impersonation — high confidence.**

---

## 1. Executive Summary

The header was from the sample uusing the `script/analyse_header.py`

```bash
python .\script\analyze_headers.py .\samples\sample-1.eml --output .\evidence\headers\sample-1-analysis.json
```

This message impersonates **Banco Bradesco / Livelo**, claiming the recipient is a “CLIENTE PRIME” and that **92,990 Livelo points are expiring today**. The visible From address uses the domain `atendimento.com.br`, while the envelope sender (`Return-Path`) is:

`root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`

The message was sent from an IP address associated with a default Ubuntu cloud server hostname, not from Bradesco or Livelo infrastructure. Authentication failed or was inconclusive:

- **SPF:** `temperror`
- **DKIM:** `none` — no signature
- **DMARC:** `temperror`
- **Microsoft compauth:** `fail reason=001`

There are no attachments, so the likely payload is a link or HTML content in the message body. The header data strongly indicates phishing.

**Risk:** High.  
**Header authentication:** Failed / not aligned.  
**Brand impersonation:** Strongly suspected.  
**Infrastructure:** Likely attacker-controlled cloud VPS.

---

## 2. Key Metadata

| Field | Value |
|---|---|
| From | `BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>` |
| To | `phishing@pot` |
| Return-Path | `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` |
| Subject | `CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!` |
| Date | `Tue, 19 Sep 2023 18:35:49 +0000` |
| Message-ID | `<20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>` |
| Attachments | None |
| DKIM signatures | 0 |

---

## 3. Authentication Analysis

| Check | Result | Notes |
|---|---|---|
| SPF | `temperror` | Sender IP `137.184.34.4`; `smtp.mailfrom=ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`; DNS timeout |
| DKIM | `none` | Message not signed |
| DMARC | `temperror` | `header.from=atendimento.com.br`; action=none due temporary error |
| Microsoft compauth | `fail` | `reason=001` |
| Return-Path alignment | Fail | Envelope sender is a local root account on an Ubuntu host, not a valid public mail domain |

### Important caveat
`temperror` is **not** a pass. It means the authentication check could not complete, often because the sending domain or hostname is invalid, non-resolvable, or misconfigured. In this case, the envelope sender is a single-label hostname:

`ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`

That is not a legitimate public email domain and does not align with `atendimento.com.br`. DKIM is absent entirely, and Microsoft’s composite authentication failed.

---

## 4. Routing and Origin Analysis

The received chain shows the message originated from a Postfix server running as root on an Ubuntu cloud instance:

1. **Origin Postfix server**  
   `by ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (Postfix, from userid 0)`  
   `id 39DEA3F725; Tue, 19 Sep 2023 18:35:49 +0000 (UTC)`

2. **Direct connection to Microsoft 365**  
   `from ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (137.184.34.4)`  
   `by BN8NAM11FT066.mail.protection.outlook.com`  
   `Tue, 19 Sep 2023 18:36:44 +0000`

3. Microsoft internal routing:
   - `BN8NAM11FT066` → `BN0PR03CA0023` → `SA3PR19MB7370` → `MN0PR19MB6312`

### Origin IP
- **Originating IP:** `137.184.34.4`
- **Hostname:** `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`
- **Mail software:** Postfix, running as `userid 0` (root)
- **Likely infrastructure:** DigitalOcean droplet, based on the default hostname pattern `sfo3` (San Francisco 3)

This is not Bradesco or Livelo infrastructure. It is consistent with an attacker-controlled VPS or a compromised cloud server used to send phishing email directly to Microsoft 365.

### Timing
Timestamps are consistent:
- Postfix queue ID time: `18:35:49 UTC`
- Outlook receipt: `18:36:44 UTC`
- Delay: ~55 seconds

No major timestamp anomaly.

---

## 5. Phishing / Suspicious Indicators

1. **Brand impersonation**  
   Display name claims `BANCO DO BRADESCO LIVELO`. The domain `atendimento.com.br` does not match official Bradesco/Livelo domains such as `bradesco.com.br` or `livelo.com.br`.

2. **Envelope/From mismatch**  
   Visible From domain: `atendimento.com.br`  
   Return-Path: `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`  
   This is a strong red flag.

3. **Invalid/non-public envelope sender**  
   The Return-Path uses a single-label hostname, not a valid domain. This causes SPF lookup failures and is not how legitimate financial institutions send mail.

4. **No DKIM signature**  
   Legitimate banks almost always sign outgoing mail with DKIM. This message has none.

5. **Authentication failure**  
   SPF `temperror`, DKIM `none`, DMARC `temperror`, compauth `fail`. The message is not authenticated.

6. **Cloud VPS origin**  
   Sending host appears to be a default Ubuntu DigitalOcean droplet with Postfix running as root. Legitimate banks do not send customer alerts from generic cloud instances.

7. **Urgency and financial lure**  
   Subject claims **92,990 Livelo points are expiring today**, pressuring the recipient to act quickly.

8. **Recipient is a phishing sinkhole**  
   `To: phishing@pot` suggests this is a reported or sinkholed phishing sample, not normal customer delivery.

9. **Message-ID uses local hostname**  
   `<20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>` is generated by the local Postfix server, not a bank mail system.

10. **No attachment**  
    The likely malicious content is in the body, such as a link to a fake Bradesco/Livelo login page or credential-harvesting site. The body was not provided in this extract.

---

## 6. Attachment Assessment

| Property | Value |
|---|---|
| Attachments | None |
| DKIM signatures | 0 |

No attachment was present. If the body contains URLs or HTML, those should be extracted and analyzed separately in a sandbox.

---

## 7. Verdict

**Phishing — high confidence.**  
The message impersonates Bradesco/Livelo, uses an urgent points-expiry lure, originates from a generic Ubuntu cloud server, fails authentication, lacks DKIM, and has a mismatched Return-Path. Header evidence strongly supports malicious intent.

**Confidence:** High for phishing based on headers and metadata.  
**Payload confidence:** Unknown without body/URL analysis.

---

## 8. Recommended Actions

1. **Block or quarantine** messages matching:
   - From domain: `atendimento.com.br` (if not legitimate for your environment)
   - Display name containing `BANCO DO BRADESCO LIVELO`
   - Subject pattern: `CLIENTE PRIME - BRADESCO LIVELO` or `pontos LIVELO expirando`
   - Return-Path containing `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`
   - Originating IP: `137.184.34.4`

2. **Search mail logs** for other messages from:
   - IP `137.184.34.4`
   - Hostname `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`
   - Message-ID prefix `20230919183549.39DEA3F725`
   - From domain `atendimento.com.br`

3. **Extract and sandbox any URLs** from the message body. Do not visit them directly.

4. **Report abuse** to DigitalOcean for IP `137.184.34.4` and to Microsoft if needed.

5. **User awareness reminder:** Bradesco and Livelo do not send points-expiry alerts from random cloud servers or unauthenticated domains. Always verify the actual sender domain, not just the display name.

6. **If any user interacted** with the message, reset credentials, review MFA, and investigate the endpoint for compromise.

---

## 9. Indicators of Compromise

| Type | Indicator |
|---|---|
| From header | `BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>` |
| Return-Path | `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` |
| Subject | `CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!` |
| Message-ID | `<20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>` |
| Originating IP | `137.184.34.4` |
| Originating hostname | `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` |
| Mail software | Postfix, `from userid 0` |
| Authentication | `spf=temperror`, `dkim=none`, `dmarc=temperror`, `compauth=fail` |
| Sample SHA256 | `35ef116a75e5e46e6859b49b60a23b4ddfe5f91d1368e0fc67a16df698cb96e0` |

---
