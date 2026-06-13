# =============================================================================
# CSV ANONYMIZER - Main Entry Point
# =============================================================================
# This file launches the application. It imports the App class from
# the app module and runs the Tkinter main loop.
#
# HOW TO RUN:
#   python main.py
#
# REQUIREMENTS:
#   pip install -r requirements.txt
# =============================================================================

import tkinter as tk                  # Standard Python GUI library
from app import CSVAnonymizerApp      # Our main application class

if __name__ == "__main__":
    # Create the root Tkinter window
    root = tk.Tk()

    # Instantiate our application (passes the window to the app)
    app = CSVAnonymizerApp(root)

    # Start the Tkinter event loop - keeps the window open
    root.mainloop()
