Public, logged-out pages of www.trustpilot.com. No account needed.

- `domain` is the business's Trustpilot address, as in `trustpilot.com/review/<domain>`
  (`metzlergmbh.de`, `www.amazon.com`), without `https://` or a path. `searchBusinesses`
  returns it.
- Page 1 has its own ops: `latestReviews` / `latestReviewsByStars`. Use `reviews` /
  `reviewsByStars` for `page=2` to `page=10`. Trustpilot redirects `?page=1` and drops every
  filter, so `page=1` is refused.
- At most 10 pages (200 reviews) per filter; page 11 and later is a login wall. For older
  reviews, narrow the filter: `reviewsByStars` gives 10 pages per star rating.
- Reviews are newest first, in all languages (`language` is the ISO code). `experiencedDate`
  is the date of the experience, often a day only. `reply` is the business's public answer and
  is missing when there is none. `verified` is Trustpilot's "Verified" label.
- A page of 20 long reviews can exceed the 20,000-character output cap and come back
  `truncated` (common on 1-star pages with long replies); the rest of that page is lost.
- In `business`, `numberOfReviews` and `ratings.total` count every review; `languages[0]`
  (`all`) and `reviewPages` count only the listed ones, and only pages 1-10 can be fetched.
- `searchBusinesses` returns the top 5 for the US site; `city` can be null.
- The first call on a new install meets Trustpilot's AWS WAF check and runs in Chrome
  (about 6-11 s); later calls are plain HTTP. If an op keeps starting in Chrome, call it
  once with `--max-tier 1`.

## Maintainer notes

Built and verified 2026-10-11, logged out, with the Rust `api-anything` 0.1.0 and headless Chromium
141 on Linux. `api-anything verify trustpilot` passed for all 7 ops, all at tier 1. The exported spec
was then installed alone into an empty `API_ANYTHING_HOME`, as the README describes: the first call
went to tier 3, then calls ran at tier 1 (see "WAF" below).

| op | args | returns | checked with (not an example) | tier |
|---|---|---|---|---|
| `searchBusinesses` | `query` | top 5 businesses: `businessUnitId`, `name`, `domain`, `numberOfReviews`, `trustScore`, `stars`, `country`, `city`, `categories`, `websiteUrl` | `query=booking`, `query=amazon` | 1 (JSON, about 0.4-0.6 s) |
| `business` | `domain` | `businessUnitId`, `name`, `domain`, `numberOfReviews`, `trustScore`, `stars`, `websiteUrl`, `country`, `categories`, `isClaimed`, `replyPercentage`, `ratings` (`one`..`five`, `total`), `languages`, `reviewPages` | `domain=www.booking.com` | 1 (page GET, about 0.6 s) |
| `latestReviews` | `domain` | newest 20 reviews: `id`, `rating`, `title`, `text`, `language`, `publishedDate`, `experiencedDate`, `consumer`, `country`, `verified`, `reply`, `likes` | `domain=www.booking.com` (7 languages, newest 2026-10-11) | 1 (about 0.5 s); 3 on a cold install |
| `reviews` | `domain`, `page` 2-10 | as `latestReviews`, for that page | `domain=www.booking.com page=4` (truncated 11 of 20) | 1 (about 0.9 s) |
| `latestReviewsByStars` | `domain`, `stars` 1-5 | as `latestReviews`, one star rating | `domain=www.zalando.de stars=2` (20 of 20 rated 2) | 1 (about 0.8 s) |
| `reviewsByStars` | `domain`, `stars`, `page` 2-10 | as `latestReviews` | `domain=www.booking.com stars=3 page=4` (20 of 20 rated 3) | 1 (about 0.8 s) |
| `topics` | `businessUnitId` | `id`, `name` per topic | `businessUnitId=46d3f1f8000064000500b592` (Booking.com, from `business`) | 1 (JSON, about 0.4 s) |

Chains:
- Reviews: `searchBusinesses query=metzler` returns `domain=metzlergmbh.de`, then call
  `latestReviews domain=metzlergmbh.de`, then `reviews domain=metzlergmbh.de page=2` ... `page=10`.
- Topics: `business domain=...` (or `searchBusinesses`) returns `businessUnitId`, then call
  `topics businessUnitId=...`.

### How it works

- The profile page `/review/<domain>` is a server-rendered Next.js page. The review ops and
  `business` read `<script id="__NEXT_DATA__">` with `--embedded 'id="__NEXT_DATA__"[^>]*>\s*([\[{])'`:
  `props.pageProps.reviews` for reviews, and `props.pageProps` (`businessUnit` plus
  `filters.reviewStatistics` and `filters.pagination`) for `business`. The request has no rotating ids.
- `searchBusinesses` is the JSON request
  `GET /api/consumersitesearch-api/businessunits/search?country=US&page=1&pageSize=5&query=...`, which
  the search results page `/search?query=...` fires on load (`--match path=...`). The same page also
  calls `/api/consumersitesearch-api/suggestions` and `/categories/search`, and the profile page calls
  `/api/consumersitesearch-api/businessunits/semantic-suggestions?countryCode=US`. None of these are
  modelled as ops.
- `topics` is `GET /api/businessunitprofile/businessunit/<id>/service-reviews/topics`. The profile page
  fires it twice on every load. It is keyed by `businessUnitId`, not the domain, so it is its own op
  with the JSON URL as its trigger.
- The page reorders the query to `languages, page, stars` with a 308. The `reviewsByStars` template
  was learned after that redirect, so tier 1 requests the canonical URL directly.
- After `add`, the search request carried New Relic tracing headers (`newrelic`, `traceparent`,
  `tracestate`: an account/app id plus a random trace id and a timestamp). They were deleted from the
  spec by hand. They are telemetry, not credentials, and the call works without them.

### Surprises

- **WAF.** On a cold Chrome profile, the first document load answers HTTP 403 with an AWS WAF
  challenge (`*.edge.sdk.awswaf.com`). Headless Chrome clears it on its own (no CAPTCHA), reloads,
  and gets an `aws-waf-token` cookie that lasts 96 h. With an empty session, a call returned
  `tier 1 was blocked (AWS WAF challenge page (HTTP 403)); tier 2 was blocked (...)` and was answered at
  tier 3 in 6.5 s. The next op answered at tier 1 in 0.4 s from the cookie jar. The escalated op kept
  starting at tier 3 (11 s) until a `--max-tier 1` call succeeded and cleared the remembered tier.
  Expect the same after the token expires.
- **`page=1` loses every filter.** `/review/<d>?languages=all&page=1` and
  `?languages=all&stars=1&page=1` both redirect (308) to the bare `/review/<d>`. That page uses the
  visitor's language (`en`) with no star filter: Metzler showed 6 English reviews instead of 1,516, and
  the 1-star call returned 5-star reviews. Hence the separate `latest*` ops.
- **Page 11 and later is a login wall**, not an empty page. `reviews ... page=11` came back
  `class: auth` ("login page instead of content"). Reported, not retried, and now refused by the
  `page` pattern.
- Profile pages also load reCAPTCHA Enterprise (`recaptcha/enterprise/anchor`) and ads, but no
  CAPTCHA was shown to read.

### Caller-note details moved here

- Without `languages=all`, Trustpilot falls back to the visitor's language (English on .com),
  so every review op asks for all languages.
- `verified` is `labels.verification.isVerified`. Metzler's newest 1-star page returned 15 of 20
  before the output cap; its all-ratings pages are about 15,000 characters and fit.
- `topics` ids (`delivery_service`, `refund`) are the topic filter values the profile page
  offers; no op filters reviews by topic yet.
- The WAF cookie lasts about 4 days (96 h); after it expires, expect the same cold start.

### Not covered

- Sorting by relevance, a single language, the `verified=true`, `replies=true`, `date=` and
  `topics=<id>` filters: each would need its own op (an op's URL has no optional parts).
- Reviews beyond page 10 of a filter (login wall), a single review by id, product reviews,
  `aiSummary` (null for the businesses checked), and the business's contact details.
- Writes (likes, reports, writing a review). This spec is read-only.
