package scanner

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"
)

// ARPScan sends ARP requests to all hosts in iface's subnet and returns IP->MAC map.
func ARPScan(iface *net.Interface, timeout time.Duration) (map[string]net.HardwareAddr, error) {
	client, err := arp.Dial(iface)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	var localIP net.IP
	var subnet *net.IPNet
	for _, addr := range addrs {
		ip, ipnet, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			localIP = ip4
			subnet = ipnet
			break
		}
	}
	if localIP == nil {
		return nil, nil
	}

	// Enumerate all IPs in subnet
	hosts := hostsInSubnet(subnet)

	// Send ARP requests concurrently
	results := make(map[string]net.HardwareAddr)
	done := make(chan struct{})

	go func() {
		deadline := time.Now().Add(timeout)
		client.SetDeadline(deadline)
		for {
			pkt, _, err := client.Read()
			if err != nil {
				break
			}
			if pkt.Operation == arp.OperationReply {
				ip := pkt.SenderIP.String()
				mac := make(net.HardwareAddr, len(pkt.SenderHardwareAddr))
				copy(mac, pkt.SenderHardwareAddr)
				results[ip] = mac
			}
		}
		close(done)
	}()

	for _, ip := range hosts {
		if ip.Equal(localIP) {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip.To4())
		if !ok {
			continue
		}
		client.Request(addr)
	}

	<-done
	return results, nil
}

func hostsInSubnet(subnet *net.IPNet) []net.IP {
	var hosts []net.IP
	ip := cloneIP(subnet.IP.Mask(subnet.Mask))
	for {
		ip = nextIP(ip)
		if !subnet.Contains(ip) {
			break
		}
		// Skip broadcast
		if isBroadcast(ip, subnet) {
			break
		}
		hosts = append(hosts, cloneIP(ip))
	}
	return hosts
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func nextIP(ip net.IP) net.IP {
	next := cloneIP(ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func isBroadcast(ip net.IP, subnet *net.IPNet) bool {
	if len(ip) != 4 {
		return false
	}
	mask := subnet.Mask
	netw := subnet.IP.To4()
	if netw == nil {
		return false
	}
	n := binary.BigEndian.Uint32(netw)
	m := binary.BigEndian.Uint32([]byte(mask))
	h := binary.BigEndian.Uint32([]byte(ip.To4()))
	broadcast := n | ^m
	return h == broadcast
}
