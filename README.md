# dnsResolver_DNSSEC
Implementation of a DNS resolver along with support for DNSSEC. In response to an input query, the resolver will first contact the root server, then the top-level domains, all the way down to the corresponding name server to resolve the DNS query.
