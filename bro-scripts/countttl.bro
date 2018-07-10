module countTTL;

@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns/
@load base/frameworks/sumstats
@load base/frameworks/sumstats/plugins/hll_unique
@load base/frameworks/sumstats/plugins/sum

export {
    redef enum Log::ID += {LOG};
	# record of values logged
    type Info: record {
        orig: addr &log; #device ip
        url: string &log; #domain name
        hits : count &log; # No. low TTL hits
        ts : time &log; #timetamp
        uniqueips : count &log; #No. unique IPs
        interv: interval &log; #interval time
		};
    }

# interval time 
global intv : interval = 15min;

event bro_init() {
    Log::create_stream(LOG,[$columns=Info, $path="countttl"]);
    # Reducer for sumstat stream, uses HLL_UNIQUE to count unique observations
    local reducer  = SumStats::Reducer($stream="countttl",
        $apply= set(SumStats::HLL_UNIQUE));

SumStats::create([$name = "count ttl ",
    $epoch = intv,
    $reducers = set(reducer),
	# function called at end of every interval, logs the number TTL answers 
	and number unique IP addresses
    $epoch_result(ts:time, key:SumStats::Key, result : SumStats::Result) = {
      local hits = result["countttl"]$num; # No. TTL hits
      Log::write(countTTL::LOG, [$orig = key$host, $url = key$str,
         $hits = hits, $ts = ts ,
         $uniqueips = result["countttl"]$hll_unique, $interv = intv]);
     }
  ]);
}