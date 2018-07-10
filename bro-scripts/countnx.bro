module Countnx;
@load base/frameworks/sumstats
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/sumstats/plugins/hll_unique
@load base/frameworks/sumstats/plugins/sum
export {
    redef enum Log::ID += {LOG};
	# record of values logged
    type Info: record {
        orig: addr &log; #host ip
		hits : count &log; #No. NXDOMAIN hits
        ts : time &log; #timestamp
        unique : count &log; #No. unique NXDOMAINs
        interv : interval &log; #interval time
        };
    }

# interval time
global intv : interval = 15min;


event bro_init() {
    Log::create_stream(LOG,[$columns=Info, $path="countnx"]);
    # reducer for sumstat stream, uses HLL_UNIQUE for unique domains
    local reducer  = SumStats::Reducer($stream="nxdomain",
        $apply= set(SumStats::HLL_UNIQUE));
    
SumStats::create([$name = "count nxdomain hits",
    $epoch = intv,
    $reducers = set(reducer),
	# function called at end of each interval, writes collected data to log
    $epoch_result(ts:time, key:SumStats::Key, result : SumStats::Result) = {
		local hits = result["nxdomain"]$num; #number of NXDOMAIN hits
        Log::write(Countnx::LOG, [$orig = key$host, $hits = hits, $ts = ts ,
		$unique = result["nxdomain"]$hll_unique, $interv = intv]);
          }
  ]);
  }