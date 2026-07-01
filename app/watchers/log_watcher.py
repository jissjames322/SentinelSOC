from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogWatcher(FileSystemEventHandler):

    def on_modified(self, event):

        print("Log updated:", event.src_path)