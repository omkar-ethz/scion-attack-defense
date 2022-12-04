package main

import (
	"fmt"
	"time"

	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"

	//pathlib "github.com/scionproto/scion/go/lib/slayers/path"
	spath "github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const (
// Global constants
)

var (
	// Here, you can define variables that keep state for your firewall
	start         time.Time
	startAddr     map[string]time.Time
	startIA       map[string]time.Time
	startSeg      map[string]map[uint16]time.Time
	nonces        *Set
	repeatedCount int
	totalCount    int
	/////
	srcIAHistogram   map[string]int // only IA
	srcAddrHistogram map[string]int //IA_IPaddr

	srcIARateHistogram   map[string]float32 // only IA
	srcAddrRateHistogram map[string]float32 //IA_IPaddr

	segIDHistogram     map[string]map[uint16]int
	segIDRateHistogram map[string]map[uint16]float32

	pathLenHistogram          map[int]int
	shortestPathToIAHistogram map[string]int

	timeWhenLastPacketReceived map[string]time.Time
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
	prettyPrintSCION(scion)
	//fmt.Println(scion.SrcIA, scion.)
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

	raw := make([]byte, scion.Path.Len())
	scion.Path.SerializeTo(raw)
	path := &spath.Decoded{}
	path.DecodeFromBytes(raw)

	// for i, info := range path.InfoFields {
	// 	t.AppendRow(table.Row{
	// 		fmt.Sprintf("InfoFields[%d]", i),
	// 		fmt.Sprintf("{Peer: %v, SegID: %d, Timestamp: %v}",
	// 			info.Peer, info.SegID, info.Timestamp),
	// 	})
	// }
	//fmt.Println(path)
	/*for _, hop := range path.HopFields {
		// t.AppendRow(table.Row{
		// 	fmt.Sprintf("HopFields[%d]", i),
		// 	fmt.Sprintf("%v", hop),
		// })
		fmt.Print(pathlib.ExpTimeToDuration(hop.ExpTime), "| ") // not informative
	}
	fmt.Println()*/

	// Hypothesis 2: Some source IA is malicious, histogram incoming packets by IA and block above a particular threshold

	// Give a quota of about
	srcIA := scion.SrcIA.String()
	srcAddr, err := scion.SrcAddr()
	segID := path.InfoFields[0].SegID
	if err != nil {
		fmt.Println("Error extracting src address")
		return false
	}
	fullSrcAddr := srcIA + "|" + srcAddr.String()
	srcIAHistogram[srcIA]++
	srcAddrHistogram[fullSrcAddr]++
	_, ok := segIDHistogram[srcIA]
	if !ok {
		segIDHistogram[srcIA] = make(map[uint16]int)
		startSeg[srcIA] = make(map[uint16]time.Time)
		segIDRateHistogram[srcIA] = make(map[uint16]float32)

	} else {
		segIDHistogram[srcIA][segID]++
	}

	// compute srcIA rate
	if srcIAHistogram[srcIA] == 1 {
		startIA[srcIA] = time.Now()
		timeWhenLastPacketReceived[srcIA] = time.Now()
		srcIARateHistogram[srcIA] = 1.0
	} else { //seeing the packet again
		srcIARateHistogram[srcIA] = float32(srcIAHistogram[srcIA]) / float32(time.Since(startIA[srcIA]).Seconds())
		// timeSinceLastPacketReceivedMillis := time.Since(timeWhenLastPacketReceived[srcIA]).Milliseconds()
		// fmt.Println(srcIA, timeSinceLastPacketReceivedMillis, timeSinceLastPacketReceivedMillis%75)
		// timeWhenLastPacketReceived[srcIA] = time.Now()
		// if timeSinceLastPacketReceivedMillis%75 < 5 || (75-(timeSinceLastPacketReceivedMillis%75)) < 5 {
		// 	return false
		// }
	}

	// compute srcAddr rate
	if srcAddrHistogram[fullSrcAddr] == 1 {
		startAddr[fullSrcAddr] = time.Now()
		srcAddrRateHistogram[fullSrcAddr] = 1.0
	} else {
		srcAddrRateHistogram[fullSrcAddr] = float32(srcAddrHistogram[fullSrcAddr]) / float32(time.Since(startAddr[fullSrcAddr]).Seconds())
	}

	//compute segID rate
	if segIDHistogram[srcIA][segID] == 1 {
		startSeg[srcIA][segID] = time.Now()
		segIDRateHistogram[srcIA][segID] = 1.0
	} else {
		segIDRateHistogram[srcIA][segID] = float32(segIDHistogram[srcIA][segID]) / float32(time.Since(startSeg[srcIA][segID]).Seconds())
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

	fmt.Println(segIDHistogram, segIDRateHistogram)

	// Hypothesis: If an IA can be reached in n hops,
	// reject all paths with >n as they might be spoofed
	// tout m'ennui les clopes la vie la nuit la bruit
	// currPathLen := path.NumHops
	// pathLenHistogram[currPathLen]++
	// fmt.Println(pathLenHistogram)
	// _, ok := shortestPathToIAHistogram[srcIA]
	// fmt.Println(shortestPathToIAHistogram)
	// if !ok {
	// 	shortestPathToIAHistogram[srcIA] = currPathLen
	// } else {
	// 	if currPathLen <= shortestPathToIAHistogram[srcIA] {
	// 		shortestPathToIAHistogram[srcIA] = currPathLen
	// 	} else {
	// 		if currPathLen > shortestPathToIAHistogram[srcIA]+1 {
	// 			fmt.Printf("rejecting as %v reachable in %v hops but got path with %v\n", srcIA, shortestPathToIAHistogram[srcIA], currPathLen)
	// 			return false
	// 		}
	// 	}
	// }

	srcIAAvg /= len(srcIAHistogram)
	srcAddrAvg /= len(srcAddrHistogram)

	//fmt.Println(srcIAAvg, srcAddrAvg, srcIAHistogram, srcAddrHistogram)
	//fmt.Println("rates: ", srcIARateHistogram, srcAddrRateHistogram)

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

	// Enforce rate per segmentID
	if segIDRateHistogram[srcIA][segID] > 3.0 {
		return false
	}

	if srcIAHistogram[srcIA] > srcIAAvg && srcAddrHistogram[fullSrcAddr] > srcAddrAvg {
		fmt.Println("Rejecting based on IA limit exceeded")
		return false
	}

	// Hypothesis x: certain path lengths are legit
	// Answer: Nahh doesn't look like it

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
	pathLenHistogram = make(map[int]int)
	shortestPathToIAHistogram = make(map[string]int)
	timeWhenLastPacketReceived = make(map[string]time.Time)

	segIDHistogram = make(map[string]map[uint16]int)
	startSeg = make(map[string]map[uint16]time.Time)
	segIDRateHistogram = make(map[string]map[uint16]float32)
	lib.RunFirewall(filter)
}
