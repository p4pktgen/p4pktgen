import logging
import time
from collections import defaultdict

from p4pktgen.config import Config


class Statistic(object):
    def __init__(self, name):
        self.name = name


class Counter(Statistic):
    def __init__(self, name):
        super(Counter, self).__init__(name)
        self.counter = 0

    def inc(self):
        self.counter += 1


class Timer(Statistic):
    def __init__(self, name):
        super(Timer, self).__init__(name)
        self.start_time = None
        self.time = 0

    def start(self):
        assert self.start_time == None
        self.start_time = time.time()

    def stop(self):
        self.time += time.time() - self.start_time
        self.start_time = None

    def get_time(self):
        return self.time

    def __repr__(self):
        return '{}: {}s'.format(self.name, self.get_time())


class Average(Statistic):
    def __init__(self, name):
        super(Average, self).__init__(name)
        self.sum = 0.0
        self.counter = 0

    def record(self, val):
        self.sum += val
        self.counter += 1

    def get_avg(self):
        if self.counter == 0:
            return None
        else:
            return self.sum / self.counter


class Statistics:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def init(self):
        self.num_control_path_edges = 0
        self.avg_full_path_len = Average('full_path_len')
        self.avg_unsat_path_len = Average('unsat_path_len')
        self.count_unsat_paths = Counter('unsat_paths')

        self.timing_file = None
        self.breakdown_file = None
        if Config().get_record_statistics():
            self.timing_file = open('timing.log', 'w')
            self.breakdown_file = open('breakdown.log', 'w')
            self.edge_file = open('edge.log', 'w')

        self.start_time = time.time()
        self.stats = defaultdict(int)
        self.stats_per_control_path_edge = defaultdict(int)
        self.last_time_printed_stats_per_control_path_edge = self.start_time
        self.record_count = 0

        self.num_test_cases = 0
        self.num_solver_calls = 0
        self.solver_time = Timer('solver_time')
        self.num_covered_edges = 0
        self.num_done = 0

    def record(self, result, record_path, path_solver):
        self.record_count += 1

        current_time = time.time()
        if record_path:
            self.timing_file.write(
                '{},{}\n'.format(result, current_time - self.start_time))
            self.timing_file.flush()
            self.edge_file.write('{},{},{}\n'.format(self.num_test_cases, self.num_covered_edges, current_time - self.start_time))
            self.edge_file.flush()
        if self.record_count % 100 == 0:
            self.breakdown_file.write('{},{},{},{},{},{}\n'.format(
                current_time - self.start_time,
                self.num_solver_calls, path_solver.total_switch_time,
                Statistics().solver_time,
                self.avg_full_path_len.get_avg(),
                self.avg_unsat_path_len.get_avg(),
                self.count_unsat_paths.counter))
            self.breakdown_file.flush()

    def log_control_path_stats(self, stats_per_control_path_edge,
                               num_control_path_edges):
        logging.info(
            "Number of times each of %d control path edges has occurred"
            " in a SUCCESS test case:", num_control_path_edges)
        num_edges_with_count = defaultdict(int)
        num_edges_with_counts = 0
        for e in sorted(stats_per_control_path_edge.keys(), key=id):
            num_edges_with_counts += 1
            cnt = stats_per_control_path_edge[e]
            num_edges_with_count[cnt] += 1
            logging.info("    %d %s" % (cnt, e))
        num_edges_without_counts = num_control_path_edges - num_edges_with_counts
        num_edges_with_count[0] += num_edges_without_counts
        logging.info("Number of control path edges covered N times:")
        for c in sorted(num_edges_with_count.keys()):
            logging.info("    %d edges occurred in %d SUCCESS test cases"
                         "" % (num_edges_with_count[c], c))

    def dump(self):
        print('num_control_path_edges', self.num_control_path_edges)
        print('num_test_cases', self.num_test_cases)
        print('num_solver_calls', self.num_solver_calls)
        print('num_covered_edges', self.num_covered_edges)
        print('num_done', self.num_done)
        print(self.solver_time)

    def cleanup(self):
        if self.timing_file is not None:
            self.timing_file.close()

        if self.breakdown_file is not None:
            self.breakdown_file.close()
