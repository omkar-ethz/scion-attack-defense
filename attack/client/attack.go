package client

import (
	// All of these imports were used for the mastersolution
	// "encoding/json"
	// "fmt"
	// "log"
	// "net"
	// "sync" // TODO uncomment any imports you need (go optimizes away unused imports)
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/snet"
	// "ethz.ch/netsec/isl/handout/attack/server"
	// "github.com/scionproto/scion/go/lib/addr"
	// "github.com/scionproto/scion/go/lib/daemon"
	// "github.com/scionproto/scion/go/lib/sock/reliable"
	// "github.com/scionproto/scion/go/lib/spath"
)

func GenerateAttackPayload() []byte {
	// TODO: Amplification Task
	return make([]byte, 0)
}

func Attack(ctx context.Context, meowServerAddr string, spoofedAddr *snet.UDPAddr, payload []byte) (err error) {

	// The following objects might be useful and you may use them in your solution,
	// but you don't HAVE to use them to solve the task.

	// Context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Here we initialize handles to the scion daemon and dispatcher running in the namespaces

	// SCION dispatcher
	/*
		dispSockPath, err := DispatcherSocket()
		if err != nil {
			log.Fatal(err)
		}
		dispatcher := reliable.NewDispatcher(dispSockPath)
	*/

	// SCION daemon
	/*
		sciondAddr, err := SCIONDAddress()
		if err != nil {
			log.Fatal(err)
		}
		sciondConn, err := daemon.NewService(sciondAddr).Connect(ctx)
		if err != nil {
			log.Fatal(err)
		}
	*/

	// TODO: Reflection Task
	// Set up a scion connection with the meow-server
	// and spoof the return address to reflect to the victim.
	// Don't forget to set the spoofed source port with your
	// personalized port to get feedback from the victims.

	// for start := time.Now(); time.Since(start) < attackDuration; {
	// }
	return nil
}
