from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switch
from datetime import datetime

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense


class SimpleMonitor13(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.model = None
        self.feature_names = []
        self._initialize_flow_training()

    def _initialize_flow_training(self):
        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        self.logger.info("Training time: %s", (end - start))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('Send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self._process_flow_stats(ev.msg.body, ev.msg.datapath.id)

    def _process_flow_stats(self, body, datapath_id):
        timestamp = datetime.now().timestamp()
        columns = self._get_flow_stat_columns()

        with open("PredictFlowStatsfile.csv", "w") as file:
            file.write(','.join(columns) + '\n')

            for stat in sorted([flow for flow in body if flow.priority == 1], key=self._flow_sort_key):
                flow_data = self._extract_flow_data(stat)
                flow_data['timestamp'] = timestamp
                flow_data['datapath_id'] = datapath_id
                flow_data['flow_id'] = self._generate_flow_id(flow_data)
                file.write(','.join(map(str, flow_data.values())) + '\n')

    def _get_flow_stat_columns(self):
        return [
            'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst',
            'tp_dst', 'ip_proto', 'icmp_code', 'icmp_type', 'flow_duration_sec',
            'flow_duration_nsec', 'idle_timeout', 'hard_timeout', 'flags',
            'packet_count', 'byte_count', 'packet_count_per_second',
            'packet_count_per_nsecond', 'byte_count_per_second', 'byte_count_per_nsecond'
        ]

    def _flow_sort_key(self, flow):
        return flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto']

    def _extract_flow_data(self, stat):
        ip_src = stat.match['ipv4_src']
        ip_dst = stat.match['ipv4_dst']
        ip_proto = stat.match['ip_proto']

        icmp_code, icmp_type, tp_src, tp_dst = self._extract_protocol_specific_fields(stat, ip_proto)

        flow_data = {
            'ip_src': ip_src, 'tp_src': tp_src, 'ip_dst': ip_dst, 'tp_dst': tp_dst,
            'ip_proto': ip_proto, 'icmp_code': icmp_code, 'icmp_type': icmp_type,
            'flow_duration_sec': stat.duration_sec, 'flow_duration_nsec': stat.duration_nsec,
            'idle_timeout': stat.idle_timeout, 'hard_timeout': stat.hard_timeout, 'flags': stat.flags,
            'packet_count': stat.packet_count, 'byte_count': stat.byte_count,
            'packet_count_per_second': self._safe_divide(stat.packet_count, stat.duration_sec),
            'packet_count_per_nsecond': self._safe_divide(stat.packet_count, stat.duration_nsec),
            'byte_count_per_second': self._safe_divide(stat.byte_count, stat.duration_sec),
            'byte_count_per_nsecond': self._safe_divide(stat.byte_count, stat.duration_nsec)
        }

        return flow_data

    def _extract_protocol_specific_fields(self, stat, ip_proto):
        icmp_code, icmp_type, tp_src, tp_dst = -1, -1, 0, 0

        if ip_proto == 1:  # ICMP
            icmp_code = stat.match['icmpv4_code']
            icmp_type = stat.match['icmpv4_type']
        elif ip_proto == 6:  # TCP
            tp_src = stat.match['tcp_src']
            tp_dst = stat.match['tcp_dst']
        elif ip_proto == 17:  # UDP
            tp_src = stat.match['udp_src']
            tp_dst = stat.match['udp_dst']

        return icmp_code, icmp_type, tp_src, tp_dst

    def _generate_flow_id(self, flow_data):
        return f"{flow_data['ip_src']}{flow_data['tp_src']}{flow_data['ip_dst']}{flow_data['tp_dst']}{flow_data['ip_proto']}"

    def _safe_divide(self, numerator, denominator):
        return numerator / denominator if denominator else 0

    def flow_training(self):
        self.logger.info("Flow Training ...")
        flow_dataset = pd.read_csv('PredictFlowStatsFile.csv')
        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

        # Exclude the last column (label) for features
        self.feature_names = flow_dataset.columns[:-1]

        X_flow = flow_dataset.iloc[:, :-1].astype(float).values
        y_flow = flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

        # Define the neural network model
        self.model = Sequential([
            Dense(64, input_dim=X_flow_train.shape[1], activation='relu'),
            Dense(32, activation='relu'),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        self.model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

        # Train the model
        self.model.fit(X_flow_train, y_flow_train, epochs=10, batch_size=10, validation_split=0.1, verbose=2)

        y_flow_pred = (self.model.predict(X_flow_test) > 0.5).astype("int32")

        self._log_model_performance(y_flow_test, y_flow_pred)

    def _log_model_performance(self, y_flow_test, y_flow_pred):
        self.logger.info("------------------------------------------------------------------------------")
        self.logger.info("Confusion Matrix:\n%s", confusion_matrix(y_flow_test, y_flow_pred))
        acc = accuracy_score(y_flow_test, y_flow_pred)
        self.logger.info("Success Accuracy: %.2f%%", acc * 100)
        self.logger.info("Fail Accuracy: %.2f%%", (1 - acc) * 100)
        self.logger.info("------------------------------------------------------------------------------")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsFile.csv')
            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

            # Align prediction data with training features
            predict_flow_dataset = predict_flow_dataset[self.feature_names]

            X_predict_flow = predict_flow_dataset.astype(float).values
            y_flow_pred = (self.model.predict(X_predict_flow) > 0.5).astype("int32")

            self._log_prediction_results(y_flow_pred, predict_flow_dataset)

            self._reset_predict_flow_stats_file()
        except Exception as e:
            self.logger.error("Error in flow_predict: %s", str(e))

    def _log_prediction_results(self, y_flow_pred, predict_flow_dataset):
        legitimate_traffic = (y_flow_pred == 0).sum()
        ddos_traffic = (y_flow_pred == 1).sum()

        self.logger.info("------------------------------------------------------------------------------")
        if (legitimate_traffic / len(y_flow_pred) * 100) > 80:
            self.logger.info("Legitimate Traffic")
        else:
            victim = predict_flow_dataset.iloc[(y_flow_pred == 1).argmax(), 5] % 20
            self.logger.info("DDoS Traffic Detected. Victim is host: h%d", victim)
        self.logger.info("------------------------------------------------------------------------------")

    def _reset_predict_flow_stats_file(self):
        columns = self._get_flow_stat_columns()
        with open("PredictFlowStatsFile.csv", "w") as file:
            file.write(','.join(columns) + '\n')
