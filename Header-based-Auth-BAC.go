package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ============================================================
// VULNERABILITIES (2 bugs):
//
//  1. MISSING AUTHENTICATION — There is no token/session
//     validation. Anyone can call /api/wallet/ unauthenticated.
//
//  2. HEADER SPOOFING / BROKEN ACCESS CONTROL —
//     userID is taken directly from the "X-Authenticated-User"
//     HTTP header, which any client can forge.
//     The server trusts an attacker-controlled value to decide
//     WHOSE wallet balances to return.
//
// FIX:
//   • Validate a signed JWT/session token from Authorization header.
//   • Extract the user identity from the verified token, NOT from
//     a raw header the client can set arbitrarily.

//curl -H "X-Authenticated-User: user-alice" http://localhost:8080/api/wallet/

// ============================================================

// Simulated wallet database
var walletDB = map[string]map[string]float64{
	"user-alice": {"BTC": 1.5, "ETH": 20.0, "USD": 5000.0},
	"user-bob":   {"BTC": 0.1, "ETH": 3.0,  "USD": 200.0},
}

func getWalletBalances(userID string) map[string]float64 {
	if bal, ok := walletDB[userID]; ok {
		return bal
	}
	return map[string]float64{}
}

func walletHandler(w http.ResponseWriter, r *http.Request) {
	// BUG 1: No authentication check — anyone can reach this handler
	// BUG 2: userID comes from a client-controlled header
	userID := r.Header.Get("X-Authenticated-User")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getWalletBalances(userID))
}

func main() {
	http.HandleFunc("/api/wallet/", walletHandler)
	fmt.Println("Server running on :8080")
	http.ListenAndServe(":8080", nil)
}
