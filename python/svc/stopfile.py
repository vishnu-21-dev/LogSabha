"""Clean stop without signals.

A service started with --stop-file PATH watches that path. When the file appears it shuts
down gracefully (so a witness can write its signed shutdown marker). This works the same on
Windows and Linux, and the launcher's `stop` command only has to create the file.
"""
import os
import threading
import time


def watch_stop_file(path, callback, interval=0.3):
    """Call callback() once when `path` exists. Runs in a daemon thread."""
    if not path:
        return None

    def run():
        while not os.path.exists(path):
            time.sleep(interval)
        callback()

    thread = threading.Thread(target=run, name="stop-file-watcher", daemon=True)
    thread.start()
    return thread


def serve_uvicorn(app, host, port, stop_file=None):
    """Run a FastAPI app until Ctrl+C or until the stop file appears."""
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    watch_stop_file(stop_file, lambda: setattr(server, "should_exit", True))
    server.run()
