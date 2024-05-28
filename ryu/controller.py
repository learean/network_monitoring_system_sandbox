import os
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import switch
from datetime import datetime
import pandas as pd
import tensorflow as tf
import joblib

class SimpleMonitor13(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        print("Training time: ", (end - start))

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
        file_path = "stats_file.csv"

        with open(file_path, "w") as file0:
            file0.write(
                'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

            body = ev.msg.body
            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow:
                (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match['ipv4_dst']
                ip_proto = stat.match['ip_proto']
                icmp_code = stat.match.get('icmpv4_code', -1)
                icmp_type = stat.match.get('icmpv4_type', -1)
                tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

                try:
                    packet_count_per_second = stat.packet_count / stat.duration_sec
                except ZeroDivisionError:
                    packet_count_per_second = 0

                try:
                    packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
                except ZeroDivisionError:
                    packet_count_per_nsecond = 0

                try:
                    byte_count_per_second = stat.byte_count / stat.duration_sec
                except ZeroDivisionError:
                    byte_count_per_second = 0

                try:
                    byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
                except ZeroDivisionError:
                    byte_count_per_nsecond = 0

                file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                            .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                    ip_proto, icmp_code, icmp_type,
                                    stat.duration_sec, stat.duration_nsec,
                                    stat.idle_timeout, stat.hard_timeout,
                                    stat.flags, stat.packet_count, stat.byte_count,
                                    packet_count_per_second, packet_count_per_nsecond,
                                    byte_count_per_second, byte_count_per_nsecond))

    def flow_training(self):
        self.logger.info("Flow Training ...")
        self.flow_model = tf.keras.models.load_model(os.path.join('../model/flow_mlp_model.h5'))
        self.flow_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        self.scaler = joblib.load(os.path.join('../model/flow_scaler.pkl'))
        self.logger.info("Model and scaler loaded and compiled successfully")

    def flow_predict(self):
        file_path = 'stats_file.csv'
        try:
            predict_flow_dataset = pd.read_csv(file_path)
            if predict_flow_dataset.empty:
                self.logger.info("No flow statistics to predict.")
                return

            self.logger.info(f"Read {len(predict_flow_dataset)} rows from {file_path}")

            # Clean and prepare data
            predict_flow_dataset['ip_src'] = predict_flow_dataset['ip_src'].astype(str).str.replace('.', '', regex=False)
            predict_flow_dataset['ip_dst'] = predict_flow_dataset['ip_dst'].astype(str).str.replace('.', '', regex=False)
            predict_flow_dataset['flow_id'] = predict_flow_dataset['flow_id'].astype(str).str.replace('.', '', regex=False)

            X_predict_flow = predict_flow_dataset.iloc[:, :-1].values
            X_predict_flow = X_predict_flow.astype('float64')

            if X_predict_flow.shape[0] == 0:
                self.logger.info("No samples available for prediction.")
                return

            X_predict_flow = self.scaler.transform(X_predict_flow)
            y_flow_pred = (self.flow_model.predict(X_predict_flow) > 0.5).astype("int32")

            legitimate_traffic = 0
            ddos_traffic = 0
            victim_ips = []
            for idx, pred in enumerate(y_flow_pred):
                if pred == 0:
                    legitimate_traffic += 1
                else:
                    ddos_traffic += 1
                    victim_ip = predict_flow_dataset.iloc[idx, predict_flow_dataset.columns.get_loc('ip_dst')]
                    victim_ips.append(victim_ip)

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_traffic / len(y_flow_pred) * 100) > 80:
                self.logger.info("legitimate traffic ...")
                self.increase_rate_limit()
            else:
                self.logger.info("ddos traffic ...")
                self.adjust_dynamic_rate_limit(ddos_traffic, legitimate_traffic)
                for victim_ip in victim_ips:
                    self.logger.info(f"Rate limiting traffic to victim: {victim_ip}")
                    self.rate_limit_victim_traffic(victim_ip)
            self.logger.info("------------------------------------------------------------------------------")

            # Clear the stats file
            with open(file_path, "w") as file0:
                file0.write(
                    'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

        except Exception as e:
            self.logger.error(f"Error in flow prediction: {e}")

    def adjust_dynamic_rate_limit(self, ddos_traffic, legitimate_traffic):
        # Adjust the rate limit based on the ratio of DDoS to legitimate traffic
        if ddos_traffic > legitimate_traffic:
            self.dynamic_rate_limit = max(100, self.dynamic_rate_limit * 0.8)  # Decrease rate limit
        else:
            self.dynamic_rate_limit = min(self.max_rate_limit, self.dynamic_rate_limit * 1.1)  # Increase rate limit

        self.logger.info(f"Adjusted dynamic rate limit to {self.dynamic_rate_limit} kbps")

    def increase_rate_limit(self):
        # Gradually increase the rate limit to the maximum value if no DDoS traffic is detected
        if self.dynamic_rate_limit < self.max_rate_limit:
            self.dynamic_rate_limit = min(self.max_rate_limit, self.dynamic_rate_limit * 1.1)
            self.logger.info(f"Increased dynamic rate limit to {self.dynamic_rate_limit} kbps")

    def rate_limit_victim_traffic(self, victim_ip):
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            # Define meter entry
            bands = [parser.OFPMeterBandDrop(rate=self.dynamic_rate_limit, burst_size=10)]
