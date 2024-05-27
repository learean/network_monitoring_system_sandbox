import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from common_utils import get_timestamp

class BaseCollectApp(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(BaseCollectApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)

    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        stats = []
        timestamp = get_timestamp()
        body = ev.msg.body
        for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow:
                           (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
            stat_dict = {
                'timestamp': timestamp,
                'datapath_id': ev.msg.datapath.id,
                'flow_id': f"{stat.match['ipv4_src']}{stat.match['tcp_src']}{stat.match['ipv4_dst']}{stat.match['tcp_dst']}{stat.match['ip_proto']}",
                'ip_src': stat.match['ipv4_src'],
                'tp_src': stat.match.get('tcp_src', 0),
                'ip_dst': stat.match['ipv4_dst'],
                'tp_dst': stat.match.get('tcp_dst', 0),
                'ip_proto': stat.match['ip_proto'],
                'icmp_code': stat.match.get('icmpv4_code', -1),
                'icmp_type': stat.match.get('icmpv4_type', -1),
                'duration_sec': stat.duration_sec,
                'duration_nsec': stat.duration_nsec,
                'idle_timeout': stat.idle_timeout,
                'hard_timeout': stat.hard_timeout,
                'flags': stat.flags,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'packet_count_per_second': stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0,
                'packet_count_per_nsecond': stat.packet_count / stat.duration_nsec if stat.duration_nsec > 0 else 0,
                'byte_count_per_second': stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0,
                'byte_count_per_nsecond': stat.byte_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
            }
            stats.append(stat_dict)
        self.write_stats_to_file(stats)

    def write_stats_to_file(self, stats):
        raise NotImplementedError("Subclasses should implement this method.")
