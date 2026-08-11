package main

import (
	"errors"
	"sync"
	"time"
)

var ErrExpired = errors.New("token is expired")

type Claims struct {
	ExpiresAt time.Time
}

type CacheEntry struct {
	Claims Claims
}

type JWTVerifier struct {
	mu    sync.RWMutex
	cache map[string]CacheEntry
}

func (v *JWTVerifier) Verify(tokenString string, claims Claims) error {
	v.mu.RLock()
	entry, found := v.cache[tokenString]
	v.mu.RUnlock()

	if found {
		if time.Now().After(entry.Claims.ExpiresAt) {
			v.mu.Lock()
			delete(v.cache, tokenString)
			v.mu.Unlock()
			return ErrExpired
		}
		return nil
	}

	// Logic to verify token signature would go here

	remaining := time.Until(claims.ExpiresAt)
	if remaining <= 0 {
		return ErrExpired
	}

	// Cache with proportional TTL
	v.mu.Lock()
	v.cache[tokenString] = CacheEntry{Claims: claims}
	v.mu.Unlock()

	return nil
}