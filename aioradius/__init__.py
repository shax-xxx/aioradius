import asyncio
import contextlib
import functools
import time
import sys

__author__ = 'arusinov'
__version__ = '0.2.6'

@contextlib.contextmanager
def execute_time(block_name, logger=None):
    start_time = time.time()
    yield
    end_time = time.time()
    if logger is not None:
        logger.debug("Block '{}' was executed by {:.4f} ms".format(block_name, (end_time - start_time) * 1000 ))
    else:
        sys.stdout.write(">>> Block '{}' was executed by {:.4f} ms\n".format(block_name, (end_time - start_time) * 1000 ))


def class_fullname(o):
    return o.__module__ + "." + o.__class__.__name__


class PeriodicTask:

    def __init__(self, loop, coro_or_func, *args, delay=1):
        self.coro = None
        self.fnc = None
        if asyncio.iscoroutinefunction(coro_or_func):
            self.coro = coro_or_func
        else:
            self.fnc = coro_or_func
        self.args = args
        self.loop = loop
        self.handle = None
        self.current_task = None
        self.delay = delay

    def run(self):
        if self.coro is not None:
            self.current_task = self.loop.create_task(self.coro(*self.args))
            self.current_task.add_done_callback(self.schedule_next)
        else:
            self.fnc(*self.args)
            self.schedule_next()

    def schedule_next(self, *args, **kwargs):
        if self.current_task is not None:
            self.current_task.remove_done_callback(self.schedule_next)
        self.handle = self.loop.call_later(self.delay, self.run)

    def start(self):
        self.handle = self.loop.call_soon(self.run)

    def stop(self):
        if self.current_task is not None:
            self.current_task.remove_done_callback(self.schedule_next)
            self.current_task.cancel()
        if self.handle is not None:
            self.handle.cancel()


def periodic_task(*decorator_args, **decorator_kwargs):
    """ Special decorator for method that will be a periodically executable """
    delay = decorator_kwargs.get('delay', 1)

    def periodic_decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper.is_periodic_task = True
        wrapper.delay = delay

        return wrapper

    return periodic_decorator

def async_cancel_tasks(loop):
    undone_tasks = []
    for task in asyncio.Task.all_tasks(loop=loop):
        try:
            if not task.done():
                task.cancel()
                undone_tasks.append(task)
        except asyncio.CancelledError:
            continue
    if undone_tasks:
        try:
            yield from asyncio.wait(undone_tasks)
        except asyncio.CancelledError:
            pass


def cancel_tasks(loop):
    undone_tasks = []
    for task in asyncio.Task.all_tasks(loop=loop):
        try:
            if not task.done():
                task.cancel()
                undone_tasks.append(task)
        except asyncio.CancelledError:
            continue

from aioradius.protocol import packet
from aioradius.client import RadiusClient, ClientDatagramEndpoint
from aioradius.server import RadiusService, RadiusResponseError, \
    RadiusAccountingProtocol, RadiusAuthProtocol, AbstractRadiusServer