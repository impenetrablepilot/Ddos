"""
run.py
------
Desktop-app launcher for ShieldChain. This is the entry point PyInstaller
builds into ddos_project.exe.

Behavior:
  - Starts the Flask server on 127.0.0.1:5000 in the background
  - Automatically opens the dashboard in the user's default browser
  - Keeps running in a console window until closed (Ctrl+C or close window)

Running as a plain script (before building the exe) works identically:
    python run.py
"""
import os
import sys
import threading
import time
import webbrowser

# Make sure app.py's relative imports (ml/, blockchain/) resolve correctly
# whether run as a script or from inside a PyInstaller bundle.
if getattr(sys, "frozen", False):
    BASE_DIR = sys._MEIPASS  # PyInstaller's temp extraction directory
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "ml"))
sys.path.insert(0, os.path.join(BASE_DIR, "blockchain"))
os.chdir(BASE_DIR)

from app import app  # noqa: E402

HOST = "127.0.0.1"
PORT = 5000
URL = f"http://{HOST}:{PORT}"


def open_browser():
    time.sleep(1.2)  # give the Flask server a moment to bind the port
    webbrowser.open(URL)


if __name__ == "__main__":
    print("=" * 52)
    print("  ShieldChain — ML/Blockchain DDoS Defense")
    print(f"  Starting server at {URL}")
    print("  Close this window (or press Ctrl+C) to stop.")
    print("=" * 52)

    threading.Thread(target=open_browser, daemon=True).start()

    # debug=False + use_reloader=False: required for a frozen exe, since the
    # reloader tries to re-exec the process, which does not work once bundled.
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
