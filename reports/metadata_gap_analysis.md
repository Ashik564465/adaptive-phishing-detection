# Metadata Gap Analysis

This analysis uses the raw files without modifying them. The email source is `data/raw/email_combined.xlsx` because `data/raw/email_combined.csv` is not present. The SMS source is `data/raw/sms_combined.csv`.

## Exact current columns

### Email

| Column | Data type | Missing % | Unique values (nonblank) | Meaning |
|---|---|---:|---:|---|
| `sender` | string | 0.76% | 29,960 | sender |
| `receiver` | string | 4.15% | 6,150 | recipient |
| `date` | string/date candidate | 1.00% | 47,058 | date/time candidate |
| `subject` | string | 0.25% | 22,012 | subject |
| `body` | string | 0.60% | 47,384 | body |
| `label` | integer-like | 0.00% | 2 | label; semantic mapping of `0/1` is unconfirmed |
| `urls` | integer-like | 0.00% | 2 | other metadata; excluded from detection |

The workbook contains 48,295 data rows. Missing percentages are calculated over data rows. Unique counts exclude blank values. The `date` values look like email date strings with offsets, but parsing, timezone normalization, and invalid-value handling still require validation.

### Ten representative email rows

Sensitive sender and recipient values are masked to the first character of the local part and domain. Bodies are truncated to 100 characters. The source values were not changed.

| # | sender | receiver | date | subject | body (masked/truncated) | label | urls |
|---:|---|---|---|---|---|---:|---:|
| 1 | `Y***@i***` | `u***@g***` | Tue, 05 Aug 2008 16:31:02 -0700 | Never agree to be a loser | Buck up, your troubles caused by small dimension will soon be over! Become a lover no woman will be... | 1 | 1 |
| 2 | `M***@i***` | `u***@g***` | Tue, 05 Aug 2008 18:31:03 -0500 | Befriend Jenna Jameson | Upgrade your sex and pleasures with these techniques http://www.brightmade.com | 1 | 1 |
| 3 | `D***@u***` | `u***@g***` | Tue, 05 Aug 2008 20:28:00 -1200 | CNN.com Daily Top 10 | >+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+= >THE DAILY TOP 10 >from CNN.com >Top v... | 1 | 1 |
| 4 | `M***@p***` | `S***@s***` | Tue, 05 Aug 2008 17:31:20 -0600 | Re: svn commit: r619753 - in /spamassassin/trunk: lib/Mail/SpamAssassin/PerMsgObject... | Would anyone object to removing .so from this list? The .so TLD is basically dead and we've found... | 0 | 1 |
| 5 | `G***@l***` | `u***@g***` | Tue, 05 Aug 2008 19:31:21 -0400 | SpecialPricesPharmMoreinfo | WelcomeFastShippingCustomerSupport http://7iwfna.blu.livefilestore.com/y1pXdX3kwzhBa8xhXv8tdHbjHn... | 1 | 1 |
| 6 | `C***@t***` | `u***@g***` | Wed, 06 Aug 2008 05:31:22 +0600 | From Caroline Aragon | Yo wu urS mo ou go rc ebo uForM rgi oreWo iyv m ww en C mo L cfd IC eym K HE uys RE!!! | 1 | 0 |
| 7 | `R***@t***` | `u***@g***` | Tue, 05 Aug 2008 21:44:01 +0000 | Replica Watches | We have fake Swiss Men's and Ladie's Replica Watches from Rolex to the Popular Panerai Watch More i... | 1 | 0 |
| 8 | `D***@t***` | `u***@g***` | Tue, 05 Aug 2008 20:41:14 -0300 | CNN.com Daily Top 10 | >+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+= >THE DAILY TOP 10 >from CNN.com >Top v... | 1 | 1 |
| 9 | `q***@i***` | `x***@s***` | Tue, 05 Aug 2008 15:31:03 -0800 | [Bug 5780] URI processing turns uuencoded strings into http URI's which then cau... | http://issues.apache.org/SpamAssassin/show_bug.cgi?id=5780 wrzzpv@sidney.com changed: ... | 0 | 1 |
| 10 | `D***@m***` | `u***@g***` | Wed, 06 Aug 2008 00:31:38 +0100 | CNN.com Daily Top 10 | >+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+= >THE DAILY TOP 10 >from CNN.com >Top v... | 1 | 1 |

The `urls` value is retained only as an audited source field. It must not become a URL reputation, blacklist, URL classification, WHOIS, or URL phishing-detection feature.

## SMS

The SMS file contains 10,430 data rows and exactly two columns. Duplicate excess rows are 2,550; the `text` column has 7,880 distinct nonblank values.

| Column | Data type | Missing % | Unique values (nonblank) | Meaning |
|---|---|---:|---:|---|
| `label` | string | 0.00% | 2 | `ham` or `spam` target label |
| `text` | string | 0.00% | 7,880 | message body/text |

There is no SMS sender, recipient, timestamp, channel-event identifier, or source field in the current file.

## Metadata availability matrix

`Available` means the current data directly contains the feature. `Partially available` means a limited or incomplete version can be derived. `Not available` means the required evidence is absent and must not be fabricated.

## Email

| Required Feature | Available | Source Column | Can Derive? | Additional Data Required |
|---|---|---|---|---|
| sender | PARTIALLY AVAILABLE | `sender` | Yes, with missing-value handling and normalization | Stable pseudonymous identity and provenance for complete coverage |
| recipient | PARTIALLY AVAILABLE | `receiver` | Yes, with missing-value handling and normalization | Stable pseudonymous identity and provenance for complete coverage |
| timestamp | PARTIALLY AVAILABLE | `date` | Yes, after parsing and timezone validation | Validated timezone/event semantics for reliable temporal analysis |
| subject | AVAILABLE | `subject` | Yes | None for basic use; retain nulls explicitly |
| body | AVAILABLE | `body` | Yes | None for basic text use; retain nulls explicitly |
| SPF | NOT AVAILABLE | None | No | Raw email headers or trusted authentication results |
| DKIM | NOT AVAILABLE | None | No | Raw email headers or trusted authentication results |
| DMARC | NOT AVAILABLE | None | No | Raw email headers or trusted authentication results |
| Reply-To | NOT AVAILABLE | None | No | Parsed email header data |
| Return-Path | NOT AVAILABLE | None | No | Parsed email header data |
| display name | NOT AVAILABLE | None | No | Parsed From display-name header |
| sender history | PARTIALLY AVAILABLE | `sender`, `date` | Limited aggregation only after validation | Historical events with stable sender IDs and trusted labels/feedback |
| sender-recipient relationship | PARTIALLY AVAILABLE | `sender`, `receiver`, `date` | Limited edge counts and first-seen values after validation | Complete historical communication events and stable IDs |
| communication frequency | PARTIALLY AVAILABLE | `sender`, `date` | Limited email-only frequency after date validation | Event timestamps, timezone, and sufficient history |
| temporal behavior | PARTIALLY AVAILABLE | `date` | Limited email-only time-of-day analysis after parsing | Valid timestamps, timezone, and historical baseline |

Email channel behavior is only PARTIALLY AVAILABLE because the email channel is identified by the file, but there are no cross-channel events in this dataset. Email authentication and header consistency checks are NOT AVAILABLE.

## SMS

| Required Feature | Available | Source Column | Can Derive? | Additional Data Required |
|---|---|---|---|---|
| sender | NOT AVAILABLE | None | No | SMS Sender ID or stable sender identifier |
| recipient | NOT AVAILABLE | None | No | Stable recipient/device identifier |
| timestamp | NOT AVAILABLE | None | No | Message event timestamp and timezone |
| subject | NOT AVAILABLE | None | No | Not normally applicable to SMS |
| body | AVAILABLE | `text` | Yes | None for basic text use |
| SPF | NOT AVAILABLE | None | No | Not applicable to SMS; do not transfer email auth assumptions |
| DKIM | NOT AVAILABLE | None | No | Not applicable to SMS; do not transfer email auth assumptions |
| DMARC | NOT AVAILABLE | None | No | Not applicable to SMS; do not transfer email auth assumptions |
| Reply-To | NOT AVAILABLE | None | No | Not applicable; sender/response metadata would be needed for any analogous analysis |
| Return-Path | NOT AVAILABLE | None | No | Not applicable to SMS |
| display name | NOT AVAILABLE | None | No | Sender display metadata, if provided by the SMS source |
| sender history | NOT AVAILABLE | None | No | Historical SMS events with stable sender IDs and validated feedback |
| sender-recipient relationship | NOT AVAILABLE | None | No | Sender, recipient, event time, and historical event records |
| communication frequency | NOT AVAILABLE | None | No | Timestamped SMS event history |
| temporal behavior | NOT AVAILABLE | None | No | Timestamped SMS event history and timezone |

## Cross-channel construction status

| Capability | Status | Reason |
|---|---|---|
| Sender profiles | PARTIALLY AVAILABLE | Email sender values support limited profiles; SMS has no sender field |
| Recipient profiles | PARTIALLY AVAILABLE | Email receiver values support limited profiles; SMS has no recipient field |
| Sender-recipient relationships | PARTIALLY AVAILABLE | Email pair records exist but lack complete historical identity/event provenance; SMS pairs are absent |
| Communication frequency | PARTIALLY AVAILABLE | Email date candidates permit limited analysis after validation; SMS has no timestamps |
| Temporal behavior | PARTIALLY AVAILABLE | Email date candidates exist; SMS has no temporal data |
| Channel behavior | NOT AVAILABLE | There is no common sender/recipient/event timeline spanning both channels |

## Precise metadata gap conclusion

The current files support direct text ingestion and a constrained email identity/behavior prototype. They do not provide authentication evidence, complete identity coverage, SMS behavioral metadata, or a cross-channel event history. Missing values must remain explicit and must not be replaced with fabricated authentication or behavioral facts.
