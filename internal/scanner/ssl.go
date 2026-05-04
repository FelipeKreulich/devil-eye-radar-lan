package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/antraz/devil-eye-lan-radar/internal/api"
)

var tlsPorts = []int{443, 8443, 4443}

// CheckSSL inspects TLS certificates on common SSL ports that are open.
func CheckSSL(ip string, services []api.Service) []api.SSLCertInfo {
	open := make(map[int]bool, len(services))
	for _, svc := range services {
		open[svc.Port] = true
	}
	var results []api.SSLCertInfo
	for _, port := range tlsPorts {
		if !open[port] {
			continue
		}
		if info := inspectCert(ip, port); info != nil {
			results = append(results, *info)
		}
	}
	return results
}

func inspectCert(ip string, port int) *api.SSLCertInfo {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", ip, port),
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec — intentional: we want to inspect even broken certs
	)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	cert := certs[0]

	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	selfSigned := cert.Issuer.String() == cert.Subject.String()
	valid := time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore)

	issuer := cert.Issuer.CommonName
	if len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}

	return &api.SSLCertInfo{
		Port:       port,
		CommonName: cert.Subject.CommonName,
		Issuer:     issuer,
		Expiry:     cert.NotAfter.Format(time.RFC3339),
		SelfSigned: selfSigned,
		Valid:       valid,
		DaysLeft:   daysLeft,
	}
}
