package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestCheckCodeLocksAfterMaxAttempts(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	h := &AuthHandler{redis: rdb}
	ctx := context.Background()

	_ = rdb.Set(ctx, "code:1", hashOTP("123456"), 10*time.Minute).Err()
	for i := 1; i < maxCodeAttempts; i++ {
		if got := h.checkCode(ctx, "code:1", "000000"); got != codeWrong {
			t.Fatalf("attempt %d: got %v, want codeWrong", i, got)
		}
	}
	if got := h.checkCode(ctx, "code:1", "000000"); got != codeLocked {
		t.Fatalf("last wrong guess should lock, got %v", got)
	}
	if got := h.checkCode(ctx, "code:1", "123456"); got != codeExpired {
		t.Fatalf("a locked code must be gone even for the right value, got %v", got)
	}

	_ = rdb.Set(ctx, "code:2", hashOTP("654321"), 10*time.Minute).Err()
	_ = h.checkCode(ctx, "code:2", "111111")
	if got := h.checkCode(ctx, "code:2", "654321"); got != codeOK {
		t.Fatalf("correct code should pass, got %v", got)
	}
	if mr.Exists("code:2") || mr.Exists("code:2:attempts") {
		t.Fatal("success must consume the code and its counter")
	}
	if got := h.checkCode(ctx, "code:2", "654321"); got != codeExpired {
		t.Fatal("a code is single use")
	}
}

func TestAllowCodeSendCapsAndExpires(t *testing.T) {
	mr := miniredis.RunT(t)
	h := &AuthHandler{redis: redis.NewClient(&redis.Options{Addr: mr.Addr()})}
	ctx := context.Background()
	for i := 0; i < maxCodeSends; i++ {
		if !h.allowCodeSend(ctx, "rate:x") {
			t.Fatalf("send %d should be allowed", i+1)
		}
	}
	if h.allowCodeSend(ctx, "rate:x") {
		t.Fatal("send over the cap must be refused")
	}
	if mr.TTL("rate:x") <= 0 {
		t.Fatal("send counter must carry a TTL")
	}
}
