package cve

import "strings"

type Entry struct {
	ID       string
	Severity string
	Desc     string
}

type rule struct {
	port    int    // 0 = any port
	pattern string // substring match on banner (lowercase), "" = match port only
	Entry
}

var rules = []rule{
	{21, "vsftpd 2.3.4", Entry{"CVE-2011-2523", "CRITICAL", "vsftpd 2.3.4 backdoor RCE"}},
	{21, "proftpd 1.3.3", Entry{"CVE-2010-4221", "CRITICAL", "ProFTPD 1.3.3c stack overflow RCE"}},
	{22, "openssh 5.", Entry{"CVE-2016-0777", "HIGH", "OpenSSH <7.1p2 memory disclosure"}},
	{22, "openssh 6.", Entry{"CVE-2016-0777", "HIGH", "OpenSSH <7.1p2 memory disclosure"}},
	{22, "openssh 7.1", Entry{"CVE-2016-0777", "HIGH", "OpenSSH 7.1p1 memory disclosure"}},
	{22, "openssh 7.2", Entry{"CVE-2016-6515", "HIGH", "OpenSSH 7.2 auth DoS"}},
	{23, "", Entry{"CVE-2001-0550", "HIGH", "Telnet plaintext credential exposure"}},
	{80, "apache/2.2.", Entry{"CVE-2017-7679", "CRITICAL", "Apache 2.2 mod_mime buffer overread"}},
	{80, "apache/2.4.49", Entry{"CVE-2021-41773", "CRITICAL", "Apache 2.4.49 path traversal + RCE"}},
	{80, "apache/2.4.50", Entry{"CVE-2021-42013", "CRITICAL", "Apache 2.4.50 path traversal bypass"}},
	{80, "apache-coyote", Entry{"CVE-2020-1938", "CRITICAL", "Apache Tomcat Ghostcat AJP file read"}},
	{80, "nginx/1.16", Entry{"CVE-2019-9511", "HIGH", "Nginx 1.16 HTTP/2 DoS"}},
	{443, "nginx/1.16", Entry{"CVE-2019-9511", "HIGH", "Nginx 1.16 HTTP/2 DoS"}},
	{445, "", Entry{"CVE-2017-0144", "CRITICAL", "EternalBlue SMB RCE (WannaCry/NotPetya)"}},
	{3306, "5.5.", Entry{"CVE-2016-6662", "CRITICAL", "MySQL 5.5 config file write → RCE"}},
	{3306, "5.6.", Entry{"CVE-2016-6662", "CRITICAL", "MySQL 5.6 config file write → RCE"}},
	{5432, "postgresql 9.", Entry{"CVE-2019-10164", "HIGH", "PostgreSQL 9.x privilege escalation"}},
	{6379, "", Entry{"CVE-2015-4335", "HIGH", "Redis unauthenticated RCE via SLAVEOF"}},
	{8080, "apache-coyote", Entry{"CVE-2020-1938", "CRITICAL", "Tomcat Ghostcat AJP file inclusion"}},
	{9200, "", Entry{"CVE-2015-1427", "CRITICAL", "Elasticsearch Groovy sandbox bypass"}},
	{27017, "", Entry{"CVE-2013-4650", "HIGH", "MongoDB default unauthenticated access"}},
}

// Match returns CVE entries for a given port and banner string.
func Match(port int, banner string) []Entry {
	lower := strings.ToLower(banner)
	seen := map[string]bool{}
	var out []Entry
	for _, r := range rules {
		if r.port != 0 && r.port != port {
			continue
		}
		if r.pattern != "" && !strings.Contains(lower, r.pattern) {
			continue
		}
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		out = append(out, r.Entry)
	}
	return out
}
