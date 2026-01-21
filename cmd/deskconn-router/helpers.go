package main

import "strings"

func extractAuthIDFromRealm(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) < 5 {
		return "", false
	}
	return parts[len(parts)-1], true
}
