"""Track and stop only the child processes created by SOC host collectors."""
import subprocess
import threading

_lock = threading.Lock()
_stopped = True
_processes = set()


def reset_collectors():
    global _stopped
    with _lock:
        if any(process.poll() is None for process in _processes):
            raise RuntimeError("Host collectors are already running")
        _processes.clear()
        _stopped = False


def spawn_collector(*args, **kwargs):
    with _lock:
        if _stopped:
            raise RuntimeError("Host collectors are stopped")
        process = subprocess.Popen(*args, **kwargs)
        _processes.add(process)
        return process


def stop_collectors():
    global _stopped
    with _lock:
        _stopped = True
        processes = list(_processes)
    for process in processes:
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
