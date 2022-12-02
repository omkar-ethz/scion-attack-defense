package main

import (
	"fmt"
	"time"

	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"
)

const (
// Global constants
)

var (
	// Here, you can define variables that keep state for your firewall
	start         time.Time
	startAddr     map[string]time.Time
	startIA       map[string]time.Time
	nonces        *Set
	repeatedCount int
	totalCount    int
	/////
	srcIAHistogram   map[string]int // only IA
	srcAddrHistogram map[string]int //IA_IPaddr

	srcIARateHistogram   map[string]float32 // only IA
	srcAddrRateHistogram map[string]float32 //IA_IPaddr
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
	srcAddr, err := scion.SrcAddr()
	if err != nil {
		fmt.Println("Error extracting src address")
		return false
	}
	fullSrcAddr := srcIA + "|" + srcAddr.String()
	srcIAHistogram[srcIA]++
	srcAddrHistogram[fullSrcAddr]++

	// compute srcIA rate
	if srcIAHistogram[srcIA] == 1 {
		startIA[srcIA] = time.Now()
		srcIARateHistogram[srcIA] = 1.0
	} else { //seeing the packet again
		srcIARateHistogram[srcIA] = float32(srcIAHistogram[srcIA]) / float32(time.Since(startIA[srcIA]).Seconds())
	}

	// compute srcAddr rate
	if srcAddrHistogram[fullSrcAddr] == 1 {
		startAddr[fullSrcAddr] = time.Now()
		srcAddrRateHistogram[fullSrcAddr] = 1.0
	} else {
		srcAddrRateHistogram[fullSrcAddr] = float32(srcAddrHistogram[fullSrcAddr]) / float32(time.Since(startAddr[fullSrcAddr]).Seconds())
	}

	srcIAAvg := 0
	srcAddrAvg := 0
	for _, v := range srcIAHistogram {
		srcIAAvg += v
	}
	for _, v := range srcAddrHistogram {
		srcAddrAvg += v
	}

	//trigger firewall after 10 reqs
	if srcAddrAvg < 10 {
		return true
	}

	srcIAAvg /= len(srcIAHistogram)
	srcAddrAvg /= len(srcAddrHistogram)

	fmt.Println(srcIAAvg, srcAddrAvg, srcIAHistogram, srcAddrHistogram)
	fmt.Println("rates: ", srcIARateHistogram, srcAddrRateHistogram)

	// Assume an SLA of xx rps per client
	if srcAddrRateHistogram[fullSrcAddr] > 3.0 {
		fmt.Println("Rejecting based on src addr rate exceeded", fullSrcAddr, srcAddrRateHistogram[fullSrcAddr])
		return false
	}

	// Enforce average SLA per IA
	if srcIARateHistogram[srcIA]/float32(srcIAHistogram[srcIA]) > 3.0 {
		fmt.Println("Rejecting based on average src IA rate exceeded", srcIA, srcIARateHistogram[srcIA])
		return false
	}

	if srcIAHistogram[srcIA] > srcIAAvg && srcAddrHistogram[fullSrcAddr] > srcAddrAvg {
		fmt.Println("Rejecting based on IA limit exceeded")
		return false
	}

	// if srcAddrHistogram[fullSrcAddr] > srcAddrAvg {
	// 	fmt.Println("Rejecting based on fullSrcAddr limit exceeded")
	// 	return false
	// }

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
	srcAddrHistogram = make(map[string]int)
	srcIARateHistogram = make(map[string]float32)
	srcAddrRateHistogram = make(map[string]float32)
	start = time.Now()
	startAddr = make(map[string]time.Time)
	startIA = make(map[string]time.Time)
	lib.RunFirewall(filter)
}
