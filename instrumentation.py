from __future__ import division
from statsd import StatsClient
from functools import wraps
import time

__all__ = ["statsd", "timing"]

statsd = StatsClient()


def timing(timer_name):
    def _timing(view_func):
        def _decorator(*args, **kwargs):
            start = time.time()
            response = view_func(*args, **kwargs)
            end = time.time()
            statsd.timing(timer_name, (end-start)*1000)
            return response
        return wraps(view_func)(_decorator)
    return _timing
