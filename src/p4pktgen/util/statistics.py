import time

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
        self.start_time = time.time()
        self.time = None

    def stop(self):
        self.time = time.time() - self.start_time

    def get_time(self):
        assert self.time is not None
        return self.time

class StatisticsRegistry:
    def __init__(self):
        pass
