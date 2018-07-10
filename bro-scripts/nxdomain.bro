module NXdomain;

@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/sumstats

export {
    redef enum Log::ID += {LOG};
	# information sent to log stream
    type Info: record {
        orig: addr &log; #host ip
        url: string &log; #domain name
        ts : time &log; #timestamp
        uid : string &log; #connection ID
        dnsip : addr &log; #IP address of the DNS server
		uid : string &log; #connection ID
        };
    }


event bro_init() {
	#creating log stream
    Log::create_stream(LOG, [$columns=Info, $path="nxdomain"]);
    }

 event dns_request(c: connection, msg: dns_msg, query : string, 
 	qtype: count, qclass :count) {
	#checks if the return code is 3
	if	(msg$rcode == 3) {
		Log::write(NXdomain::LOG, [$orig = c$id$orig_h,
			$url = query,
			$timestamp = network_time(),
			$uid= c$uid,
			$dnsip=c$id$resp_h,
			$uid = c$uid]);
		#adds observation the sumstat stream
		SumStats::observe("nxdomain",
			SumStats::Key($host = c$id$orig_h),
			SumStats::Observation($str=query));
 	}
 }