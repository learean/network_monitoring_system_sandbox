from base_collect import BaseCollectApp
from common_utils import write_flow_stats

class CollectBenignTrafficApp(BaseCollectApp):
    def __init__(self, *args, **kwargs):
        super(CollectBenignTrafficApp, self).__init__(*args, **kwargs)
        with open("FlowStatsfile.csv", "w") as file:
            file.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,label\n')

    def write_stats_to_file(self, stats):
        with open("FlowStatsfile.csv", "a+") as file:
            write_flow_stats(file, stats, 0)

app_manager.require_app('collect_benign')
