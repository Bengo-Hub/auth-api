# Legal documents

I manage every platform policy and agreement from the auth-ui dashboard (Platform, Legal Documents, at `/dashboard/platform/legal`). The model follows Hadia's legal module: one row per version, drafts that only platform admins see, a publish step with an effective date, and re-acceptance after a material change. auth-api owns the documents and the acceptances; other services read them through the public or S2S routes below.

## Document types

| Type | Kind | How a version comes into force | Who accepts |
|---|---|---|---|
| TERMS_OF_SERVICE | user consent | effective date | each user |
| PRIVACY_POLICY | user consent | effective date | each user |
| COOKIE_POLICY | notice | effective date | nobody |
| REFUND_POLICY | notice | effective date | nobody |
| DATA_REQUESTS | notice | effective date | nobody |
| MARKETFLOW_AUTOPUBLISH_TERMS | product terms | effective date | the tenant (MarketFlow may record it by S2S) |
| MSA, DPA, EPA, RESELLER_AGREEMENT | agreement | `is_current` | the tenant or equity holder, signed in |

For an effective-dated type the version in force is the newest published one whose date has passed, and a later one is "upcoming". Superseded is worked out from that timeline and never stored.

## Versions

- A version is a draft or published (`status`). A type has at most one draft at a time; saving a second version while one is open answers 409 `draft_exists`.
- Title, change summary, the material flag and who edited or published a version sit in the `metadata` JSON column (`title`, `summary`, `material`, `updated_by`, `published_by`, `published_at`).
- Publishing an effective-dated draft needs the minimum notice (`LEGAL_MIN_NOTICE_DAYS`, `LEGAL_MIN_NOTICE_DAYS_BY_TYPE`, 14 days unless set). `skip_notice` is for an urgent change; with no date it puts the version in force now.
- Publishing an agreement draft makes it the only current version of its type, in one transaction.
- A published version is never edited once it is in force or anyone has accepted it, and never deleted. A change is a new version.

## Re-acceptance

Only the Terms of Service and the Privacy Policy carry the material flag. A user's sign-up acceptance (`users.terms_accepted_at`) covers every version in force when they signed up. When a material version comes into force after that, `GET /api/v1/auth/legal/pending` lists the version in force under `required` until the user accepts it (or a later version) with `POST /api/v1/auth/legal/accept`. A material version announced for later is listed under `upcoming`. auth-ui shows the banner on every dashboard page.

## Public pages

auth-ui's `/terms-of-service`, `/privacy`, `/cookies`, `/refund-policy` and `/data-requests` show the published version from auth-api, with a notice and link for an upcoming one, and keep their built-in text until a first version is published. Each has a `/{version}` page for older and upcoming versions. The editor can start a first version from the built-in page text.

## Routes

| Method and path | Who | What |
|---|---|---|
| GET `/api/v1/legal/documents/{type}` | public | version in force and upcoming one |
| GET `/api/v1/legal/documents/{type}/versions[/{version}]` | public | published versions |
| POST `/api/v1/auth/legal/accept` | signed in | accept a version |
| GET `/api/v1/auth/legal/pending` | signed in | re-acceptance owed |
| GET `/api/v1/admin/legal/overview` | platform admin | every type with its state and history |
| GET `/api/v1/admin/legal/documents/{type}/versions[/{version}]` | platform admin | drafts included |
| PUT `/api/v1/admin/legal/documents/{type}/drafts/{version}` | platform admin | save a draft |
| POST `/api/v1/admin/legal/documents/{type}/drafts/{version}/publish` | platform admin | publish |
| DELETE `/api/v1/admin/legal/documents/{type}/drafts/{version}` | platform admin | discard a draft |
| GET, POST `/api/v1/s2s/tenants/{tenant_id}/legal/acceptances` | services | product terms only |

## Not done yet

Users learn about a new version in the app (banner) and on the public pages. An email notice to every user when a material version is published is not built yet; it belongs in notifications-api, fed by an auth-api event.
