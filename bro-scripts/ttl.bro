module DNSTTL;
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns/
@load base/frameworks/sumstats
@load base/utils/addrs.bro

export {
    redef enum Log::ID += {LOG};
	# record of values logged
    type Info: record {
        orig: addr &log; #host ip
        dnsip : addr &log; #ip of dns server
        url: string &log; #domain name
        ts : time &log; #timestamp
        uid : string &log; #connection ID
        ttl : interval &log; #TTL in seconds
        ip : addr &log; #IP address of request server 
		uid : string &log; #connection ID
        };
    }
# the ttlvalue of threshold, current 298 to avoid 299 CDN
global ttlvalue : interval = 298sec;

event bro_init() {
    Log::create_stream(LOG, [$columns=Info, $path="ttl"]);
    }


function log_ttl(c:connection, ans:dns_answer, a:addr) {
	# if TTL value below threshold entries are written to log.
    if (ans$TTL <= ttlvalue) {
        Log::write(DNSTTL::LOG, [$orig = c$id$orig_h,
        $dnsip = c$id$resp_h,
	    $url = ans$query,
	    $ts = network_time(),
        $uid= c$uid,
        $ttl = ans$TTL,
        $ip = a,
		$uid = c$uid]);
	# adding observation to sumstats stream
    SumStats::observe("countttl",
        SumStats::Key($str=ans$query, $host = c$id$orig_h),
        SumStats::Observation($str = addr_to_uri(a)));
    }
}
# handles DNS A records answers
event dns_A_reply (c:connection, msg: dns_msg, ans: dns_answer, a:addr) {
    log_ttl(c, ans, a);
}
# handles DNS AAAA records answers
event dns_AAAA_reply(c:connection, msg: dns_msg, ans: dns_answer, a:addr) {
    log_ttl(c, ans, a);
    
}
