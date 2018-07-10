module NXdomainID;

@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/sumstats
@load base/utils/active-http.bro
export {
    redef enum Log::ID += {LOG};
	# information sent to log stream
    type Info: record {
        orig: addr &log; #host ip
        url: string &log; #domain name
        class : string &log;
    };
    }


event bro_init() {
	#creating log stream
    Log::create_stream(LOG, [$columns=Info, $path="nxdomainID"]);

    local reducer = SumStats::Reducer($stream="predicteddga",
        $apply = set(SumStats::SUM));

SumStats::create([$name = "predicted dga hits",
    $epoch = 15min,
    $reducers = set(reducer),
      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
       {
       return result["predicteddga"]$sum;
       },
    $threshold = 10.0,
    $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
         {
         print fmt("IP addres : %s is most likely infected with malware", SumStats::key2str(key));
     }
  
 ]);
}
event DNS::log_dns(rec: DNS::Info) {
    if	(rec ?$ rcode && rec$rcode == 3) {
        local request = [$url = "localhost:8080", $method="POST",
            $client_data=string_cat("domain=", rec$query), $max_time=10sec];
        when ( local resp = ActiveHTTP::request(request)) {
            Log::write(NXdomainID::LOG, [$orig = rec$id$orig_h,
			$url = rec$query,
            $class = resp$body]);
        if (resp$body == "dga") {
            #adds observation the sumstat stream
		    SumStats::observe("predicteddga",
			SumStats::Key($host = rec$id$orig_h),
		    SumStats::Observation($num=1));
            }
        }
    }
}

 # event dns_request(c: connection, msg: dns_msg, query : string, 
 # 	qtype: count, qclass :count) {
 #    #checks if the return code is 3
 #    if	(msg$rcode == 3) {
 #    	Log::write(NXdomainID::LOG, [$orig = c$id$orig_h,
 #    		$url = query,
 #    		$timestamp = network_time(),
 #    		$uid= c$uid,
 #    		$dnsip=c$id$resp_h,
 #    		$uid = c$uid]);
 #    	#adds observation the sumstat stream
 #    	#SumStats::observe("nxdomain",
 #    		#SumStats::Key($host = c$id$orig_h),
 #    	#SumStats::Observation($str=query));
 #        print "performing request";
 #        when ( local result = ActiveHTTP::Request($url = "localhost:8080", $method="POST",
 #            $client_data=string_cat("domain=", query), $max_time=10sec)) {
 #        print result;
 #        }
 # 	}
 # }