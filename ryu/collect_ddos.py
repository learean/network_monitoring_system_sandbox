from base_collect import BaseCollectApp
from common_utils import write_flow_stats

class CollectDDOSTrafficApp(BaseCollectApp):
    def __init__(self, *args, **kwargs):
        super(CollectDDOSTrafficApp, self).__init__(*args, **kwargs)

    def write_stats_to_file(self, stats):
        with open("FlowStatsfile.csv", "a+") as file:
            write_flow_stats(file, stats, 1)
