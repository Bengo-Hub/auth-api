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

## Email notice

Publishing a material Terms of Service or Privacy Policy version emails every active user. auth-api writes one `auth.legal.updated.notify` outbox event per user, in batches of 500, and notifications-api sends the email, keyed per user and version so a rerun never mails anyone twice (`legal_notify.go`). The email links to the version's page on auth-ui. Users also see the banner in the app and the notice on the public pages.

## Seeded first versions

The first version of each platform policy and of the MarketFlow Autopilot terms is built into auth-api as HTML in `internal/seed/legal/*.html` (embedded with `go:embed`):

| File | Type |
|---|---|
| `terms-of-service.html` | TERMS_OF_SERVICE |
| `privacy-policy.html` | PRIVACY_POLICY |
| `cookie-policy.html` | COOKIE_POLICY |
| `refund-policy.html` | REFUND_POLICY |
| `data-requests.html` | DATA_REQUESTS |
| `marketflow-autopublish-terms.html` | MARKETFLOW_AUTOPUBLISH_TERMS |

`cmd/seed` publishes each one as version `1`, in force from the start of the day it runs (UTC), but only for a type that has no version at all. A type that already has a version is left alone, so a second run changes nothing and never touches what I published from the dashboard. The seeder goes through the same insert and publish steps as the dashboard (`insertDraft` and `publishDraftRow` in `legal_drafts.go`, called from `SeedFirstVersion` in `legal_seed.go`). The notice period does not apply, because nothing was published before, and no email goes out, because version 1 is not marked material. If a run stops between the two steps, the next run publishes the seeded draft it left.

The full seed runs this as its last step. `SEED_ONLY=legal /app/seed` runs only this step and touches nothing else.

Every `<h2>` in these files has a stable `id` that matches the anchors of the built-in pages (`#google-signin`, `#meta-data`, `#youtube`, `#tiktok`, `#sub-processors` and so on). auth-ui builds the Contents list from those ids. The built-in TSX pages in auth-ui carry the same text as the fallback, so both read the same. Any later change is a new version from the dashboard, not an edit of these files; editing a file after it was seeded has no effect on a database that already has version 1.

## Repository revisions

A change that has to ship with the code that needs it is written in the repository as a new version, never as an edit of a seeded file. `legal.Revisions` in `internal/seed/legal/legal.go` lists them, each with its own HTML file, the version it follows and a change summary. After the first versions, `cmd/seed` publishes each revision through `SeedRevision` in `legal_seed.go`, with the same insert and publish steps as the dashboard:

- only while the version it follows is still the newest version of the type and no draft is open, so a type I have changed in the dashboard is left alone;
- once: a second run finds the revision published and skips it, and a run stopped between the two steps publishes the draft it left;
- as a non-material change in force from the day it is seeded, so nobody is asked to accept again and no email goes out. A material change goes through the dashboard, which gives notice and emails every user.

| File | Type | Version | Change |
|---|---|---|---|
| `privacy-policy-v2.html` | PRIVACY_POLICY | 2 (after 1) | Section 5G, Login with TikTok |

## Social sign-in tokens

Social sign-in (Google, GitHub, Microsoft, TikTok) no longer keeps the provider's access token or refresh token on `user_identities`. Sign-in uses them only for the profile call and nothing reads them later, as the privacy policy (section 5A) says. The provider subject, email, scope, expiry and profile are still stored. Migration `20261119120000_clear_identity_oauth_tokens.sql` records the change that nulls the tokens already stored. Because auth-api migrates with `Schema.Create`, which does not execute the versioned files, `database.ClearIdentityOAuthTokens` runs the same idempotent update after every migrate.
