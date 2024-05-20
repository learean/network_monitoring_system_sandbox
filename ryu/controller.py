import os

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switch
from datetime import datetime
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model


class SimpleMonitor13(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # Load the pre-trained model
        self.flow_model = load_model(os.path.join('../model/ddos_detection_model.h5'))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()

        with open("PredictFlowStatsfile.csv", "w") as file0:
            file0.write(
                'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            body = ev.msg.body
            icmp_code = -1
            icmp_type = -1
            tp_src = 0
            tp_dst = 0

            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (
            flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match['ipv4_dst']
                ip_proto = stat.match['ip_proto']

                if stat.match['ip_proto'] == 1:
                    icmp_code = stat.match['icmpv4_code']
                    icmp_type = stat.match['icmpv4_type']
                elif stat.match['ip_proto'] == 6:
                    tp_src = stat.match['tcp_src']
                    tp_dst = stat.match['tcp_dst']
                elif stat.match['ip_proto'] == 17:
                    tp_src = stat.match['udp_src']
                    tp_dst = stat.match['udp_dst']

                flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

                try:
                    packet_count_per_second = stat.packet_count / stat.duration_sec
                    packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
                except ZeroDivisionError:
                    packet_count_per_second = 0
                    packet_count_per_nsecond = 0

                try:
                    byte_count_per_second = stat.byte_count / stat.duration_sec
                    byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
                except ZeroDivisionError:
                    byte_count_per_second = 0
                    byte_count_per_nsecond = 0

                file0.write(
                    f"{timestamp},{ev.msg.datapath.id},{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},{stat.match['ip_proto']},{icmp_code},{icmp_type},{stat.duration_sec},{stat.duration_nsec},{stat.idle_timeout},{stat.hard_timeout},{stat.flags},{stat.packet_count},{stat.byte_count},{packet_count_per_second},{packet_count_per_nsecond},{byte_count_per_second},{byte_count_per_nsecond}\n")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

            # Convert string IPs to integer-like format for prediction
            predict_flow_dataset['flow_id'] = predict_flow_dataset['flow_id'].str.replace('.', '', regex=False)
            predict_flow_dataset['ip_src'] = predict_flow_dataset['ip_src'].str.replace('.', '', regex=False)
            predict_flow_dataset['ip_dst'] = predict_flow_dataset['ip_dst'].str.replace('.', '', regex=False)

            # Select only the columns used for prediction
            X_predict_flow = predict_flow_dataset[[
                'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst',
                'ip_proto', 'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec',
                'idle_timeout', 'hard_timeout', 'flags', 'packet_count', 'byte_count',
                'packet_count_per_second', 'packet_count_per_nsecond', 'byte_count_per_second',
                'byte_count_per_nsecond'
            ]].values.astype('float64')

            y_flow_pred = (self.flow_model.predict(X_predict_flow) > 0.5).astype("int32")

            legitimate_traffic = np.sum(y_flow_pred == 0)
            ddos_traffic = np.sum(y_flow_pred == 1)

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_traffic / len(y_flow_pred) * 100) > 80:
                self.logger.info("legitimate traffic ...")
            else:
                self.logger.info("ddos traffic ...")
                # Assuming victim host can be derived somehow; adjust as necessary
                victims = predict_flow_dataset.loc[y_flow_pred == 1, 'ip_dst'].unique()
                for victim in victims:
                    self.logger.info(f"victim might be host with ip_dst: {victim}")
            self.logger.info("------------------------------------------------------------------------------")

            # Clear the file after processing
            with open("PredictFlowStatsfile.csv", "w") as file0:
                file0.write(
                    'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

        except Exception as e:
            self.logger.error(f"Error in flow_predict: {e}")
            pass
