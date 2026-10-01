package handlers

import (
	"context"
	"net/http"

	"github.com/redis/go-redis/v9"
)

// maxCodeAttempts is how many wrong guesses a one-time code survives. A 6-digit code has a
// million values, so 5 guesses per issued code (and at most 5 codes per 10 minutes) keeps a
// brute force at roughly 1 in 40,000 per 10 minutes instead of near-certain within the TTL.
const maxCodeAttempts = 5

type codeCheck int

const (
	codeExpired codeCheck = iota // no pending code
	codeOK                       // matched and consumed
	codeWrong                    // mismatch, attempts left
	codeLocked                   // too many mismatches, code destroyed
)

// checkCodeScript compares the stored hash (KEYS[1]) with ARGV[1] in one atomic step, so
// parallel guesses on different pods cannot each get a free try. A match deletes the code and
// its attempt counter (one use only). A mismatch increments the counter (KEYS[2]), which lives
// exactly as long as the code; the maxCodeAttempts-th mismatch destroys the code.
var checkCodeScript = redis.NewScript(`
local stored = redis.call("GET", KEYS[1])
if not stored then return 0 end
if stored == ARGV[1] then
  redis.call("DEL", KEYS[1], KEYS[2])
  return 1
end
local n = redis.call("INCR", KEYS[2])
if n == 1 then
  local ttl = redis.call("PTTL", KEYS[1])
  if ttl <= 0 then ttl = 600000 end
  redis.call("PEXPIRE", KEYS[2], ttl)
end
if n >= tonumber(ARGV[2]) then
  redis.call("DEL", KEYS[1], KEYS[2])
  return 3
end
return 2`)

// checkCode verifies a submitted one-time code against the hash stored at codeKey.
func (h *AuthHandler) checkCode(ctx context.Context, codeKey, submitted string) codeCheck {
	n, err := checkCodeScript.Run(ctx, h.redis, []string{codeKey, codeKey + ":attempts"},
		hashOTP(submitted), maxCodeAttempts).Int()
	if err != nil {
		return codeExpired
	}
	return codeCheck(n)
}

// writeCodeError maps a failed checkCode result to the API's existing error codes.
func writeCodeError(w http.ResponseWriter, res codeCheck, prefix string) {
	switch res {
	case codeWrong:
		writeError(w, http.StatusBadRequest, prefix+"_invalid", "The code is incorrect.", nil)
	case codeLocked:
		writeError(w, http.StatusTooManyRequests, prefix+"_locked",
			"Too many incorrect attempts. Request a new code.", nil)
	default:
		writeError(w, http.StatusBadRequest, prefix+"_expired", "The code has expired or was not sent. Request a new one.", nil)
	}
}

// maxCodeSends caps how many codes one user or email can request per codeSendWindow.
const maxCodeSends = 5

const codeSendWindowSeconds = 600

// sendCounterScript increments and sets the window TTL in one step, so a crash between the
// two calls can never leave a counter that blocks the user forever.
var sendCounterScript = redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
if redis.call("TTL", KEYS[1]) < 0 then redis.call("EXPIRE", KEYS[1], ARGV[1]) end
return n`)

// allowCodeSend reports whether another code may be sent for rateKey. It allows the send when
// Redis errors, matching the previous behavior (the send path itself needs Redis anyway).
func (h *AuthHandler) allowCodeSend(ctx context.Context, rateKey string) bool {
	n, err := sendCounterScript.Run(ctx, h.redis, []string{rateKey}, codeSendWindowSeconds).Int()
	if err != nil {
		return true
	}
	return n <= maxCodeSends
}
