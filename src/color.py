# color.py - Terminal color handling for chat application
import random
import os

# ANSI color codes for terminal
COLORS = {
    'RESET': '\033[0m',
    'GREEN': '\033[92m',
    'CYAN': '\033[96m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'MAGENTA': '\033[95m',
    'RED': '\033[91m',
    'BRIGHT_GREEN': '\033[1;92m',
    'BRIGHT_CYAN': '\033[1;96m',
    'BRIGHT_YELLOW': '\033[1;93m',
    'BRIGHT_BLUE': '\033[1;94m',
    'BRIGHT_MAGENTA': '\033[1;95m',
    'BRIGHT_RED': '\033[1;91m'
}

# List of colors for users (excluding green which is reserved for system messages)
USER_COLORS = [
    COLORS['CYAN'], COLORS['YELLOW'], COLORS['BLUE'],
    COLORS['MAGENTA'], COLORS['RED'], COLORS['BRIGHT_CYAN'],
    COLORS['BRIGHT_YELLOW'], COLORS['BRIGHT_BLUE'],
    COLORS['BRIGHT_MAGENTA'], COLORS['BRIGHT_RED']
]

# System message color
SYSTEM_COLOR = COLORS['GREEN']

class ColorManager:
    def __init__(self):
        self.user_colors = {}  # username -> color
        # Initialize random seed for consistent colors
        random.seed(os.urandom(4))

    def get_user_color(self, username):
        """Get or assign a color for a user"""
        if username not in self.user_colors:
            self.user_colors[username] = random.choice(USER_COLORS)
        return self.user_colors[username]

    def print_system_message(self, message):
        """Print a system message in green"""
        print(f"\r{SYSTEM_COLOR}{message}{COLORS['RESET']}")

    def print_user_message(self, username, message):
        """Print a user message with the user's color"""
        color = self.get_user_color(username)
        print(f"\r{color}{username}{COLORS['RESET']}: {message}")

    def show_prompt(self, username):
        """Show the user input prompt"""
        print(f"{username}> ", end="", flush=True)