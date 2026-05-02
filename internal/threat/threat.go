package threat

import "strings"

type Hit struct {
	Category string
	Message  string
}

// Check returns a threat hit if domain or IP is known-malicious.
func Check(indicator string) (bool, Hit) {
	indicator = strings.ToLower(strings.TrimSpace(indicator))
	if indicator == "" {
		return false, Hit{}
	}
	// Check exact match first
	if h, ok := badDomains[indicator]; ok {
		return true, h
	}
	// Check suffix (subdomain of bad domain)
	for bad, h := range badDomains {
		if strings.HasSuffix(indicator, "."+bad) {
			return true, h
		}
	}
	// Check IP ranges
	if h, ok := badIPs[indicator]; ok {
		return true, h
	}
	return false, Hit{}
}

var badDomains = map[string]Hit{
	// ── Botnets / C2 ────────────────────────────────────────────────
	"emotet.pw":                   {"Botnet", "Emotet C2"},
	"trickbot.cc":                 {"Botnet", "TrickBot C2"},
	"bazarbackdoor.com":           {"Botnet", "BazarBackdoor C2"},
	"cobaltstrike.rocks":          {"C2", "Cobalt Strike beacon"},
	"metasploit.com":              {"C2", "Metasploit C2"},
	"c2.evil.com":                 {"C2", "Known C2 framework"},

	// ── Malware delivery ────────────────────────────────────────────
	"malware-traffic-analysis.net": {"Malware", "Malware delivery (research)"},
	"eicar.org":                    {"Malware", "EICAR test file"},

	// ── Stalkerware / Spyware ────────────────────────────────────────
	"mspy.com":         {"Spyware", "mSpy stalkerware"},
	"flexispy.com":     {"Spyware", "FlexiSpy stalkerware"},
	"hoverwatch.com":   {"Spyware", "Hoverwatch stalkerware"},
	"spyic.com":        {"Spyware", "Spyic stalkerware"},
	"cocospy.com":      {"Spyware", "Cocospy stalkerware"},

	// ── Cryptominers ────────────────────────────────────────────────
	"coinhive.com":           {"Miner", "CoinHive cryptominer (defunct)"},
	"coin-hive.com":          {"Miner", "CoinHive cryptominer"},
	"jsecoin.com":            {"Miner", "JSEcoin cryptominer"},
	"cryptoloot.pro":         {"Miner", "CryptoLoot miner"},
	"minero.cc":              {"Miner", "In-browser miner"},
	"webminepool.com":        {"Miner", "In-browser miner"},
	"monero.cryptocurrency-js.com": {"Miner", "Monero browser miner"},

	// ── Phishing kits / typosquatting ───────────────────────────────
	"paypa1.com":       {"Phishing", "PayPal phishing"},
	"g00gle.com":       {"Phishing", "Google phishing"},
	"arnazon.com":      {"Phishing", "Amazon phishing"},
	"appleid-support.com": {"Phishing", "Apple phishing"},
	"faceb00k.com":     {"Phishing", "Facebook phishing"},
	"rnicrosoft.com":   {"Phishing", "Microsoft phishing"},

	// ── Known ad/tracking (aggressive) ──────────────────────────────
	"doubleclick.net":      {"Tracker", "Google DoubleClick tracker"},
	"googlesyndication.com": {"Tracker", "Google ad tracker"},
	"scorecardresearch.com": {"Tracker", "Comscore tracker"},
	"quantserve.com":       {"Tracker", "Quantcast tracker"},
	"addthis.com":          {"Tracker", "AddThis social tracker"},
	"outbrain.com":         {"Tracker", "Outbrain content tracker"},
	"taboola.com":          {"Tracker", "Taboola content tracker"},

	// ── Tor / Proxies ────────────────────────────────────────────────
	"torproject.org":   {"Anonymizer", "Tor Project"},
	"proxysite.com":    {"Anonymizer", "Public proxy service"},
	"hide.me":          {"Anonymizer", "VPN/proxy service"},
	"hidemy.name":      {"Anonymizer", "Proxy service"},

	// ── Data exfiltration patterns ───────────────────────────────────
	"pastebin.com":     {"Exfil", "Common exfiltration target"},
	"paste.ee":         {"Exfil", "Common exfiltration target"},
	"hastebin.com":     {"Exfil", "Common exfiltration target"},
	"transfer.sh":      {"Exfil", "Anonymous file transfer"},
	"anonfiles.com":    {"Exfil", "Anonymous file sharing"},
	"gofile.io":        {"Exfil", "Anonymous file sharing"},

	// ── Remote access tools (suspicious) ────────────────────────────
	"ngrok.io":         {"RAT", "ngrok tunneling (common in attacks)"},
	"ngrok.com":        {"RAT", "ngrok tunneling"},
	"pagekite.net":     {"RAT", "Reverse tunnel service"},
	"serveo.net":       {"RAT", "Reverse SSH tunnel"},
}

// Known malicious IPs (examples — expand with live threat feeds)
var badIPs = map[string]Hit{
	"185.220.101.0":  {"TorExit", "Tor exit node"},
	"45.142.212.100": {"C2", "Known malware C2 IP"},
	"91.108.4.0":     {"Scan", "Aggressive scanner IP"},
}
