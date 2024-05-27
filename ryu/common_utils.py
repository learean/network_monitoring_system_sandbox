from datetime import datetime

def get_timestamp():
    timestamp = datetime.now()
    return timestamp.timestamp()

def ip_generator():
    from random import randrange
    return f"10.0.0.{randrange(1, 19)}"

def write_flow_stats(file, stats, label):
    for stat in stats:
        file.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                   .format(stat['timestamp'], stat['datapath_id'], stat['flow_id'], stat['ip_src'],
                           stat['tp_src'], stat['ip_dst'], stat['tp_dst'], stat['ip_proto'],
                           stat['icmp_code'], stat['icmp_type'], stat['duration_sec'],
                           stat['duration_nsec'], stat['idle_timeout'], stat['hard_timeout'],
                           stat['flags'], stat['packet_count'], stat['byte_count'],
                           stat['packet_count_per_second'], stat['packet_count_per_nsecond'],
                           stat['byte_count_per_second'], stat['byte_count_per_nsecond'], label))
