package main

import (
	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"
)

const (
// Global constants
)

var (
	// Here, you can define variables that keep state for your firewall
	nonces        *Set
	repeatedCount int
	totalCount    int
	/////
	srcIAHistogram map[string]int
)

// This function receives all packets destined to the customer server.
//
// Your task is to decide whether to forward or drop a packet based on the
// headers and payload.
// References for the given packet types:
//   - SCION header
//     https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#SCION
//   - UDP header
//     https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#UDP
type clientRequest map[string]int

func filter(scion slayers.SCION, udp slayers.UDP, payload []byte) bool {
	// Print packet contents (disable this before submitting your code)
	//prettyPrintSCION(scion)
	//prettyPrintUDP(udp)

	// Hypothesis 1: The attacker sends repeated nonces or ill-formed messages?
	/*totalCount++
	var req clientRequest
	json.Unmarshal(udp.Payload, &req)
	nonce := req["NonceB"]
	if nonces.Has(nonce) {
		fmt.Println("Repeated nonce")
		repeatedCount++
		return false
	}
	nonces.Add(nonce)
	fmt.Println("repeated/total:", repeatedCount, "/", totalCount)*/
	// Hyptothesis 1 falsified, no repeated nonces in either def1-3 scenarios, all udp payloads well-formed

	// Hypothesis 2: Some source IA is malicious, histogram incoming packets by IA and block above a particular threshold

	// Give a quota of about
	srcIA := scion.SrcIA.String()
	srcIAHistogram[srcIA]++

	avg := 0
	for _, v := range srcIAHistogram {
		avg += v
	}
	avg /= len(srcIAHistogram)

	//fmt.Println(avg, srcIAHistogram)

	if srcIAHistogram[srcIA] > avg {
		return false
	}
	// Hypothesis 3: Signature does not verify for attacker packets

	// Decision
	// | true  -> forward packet
	// | false -> drop packet
	return true
}

func init() {
	// Perform any initial setup here
}

func main() {
	// Start the firewall. Code after this line will not be executed
	nonces = NewSet()
	srcIAHistogram = make(map[string]int)
	lib.RunFirewall(filter)
}
