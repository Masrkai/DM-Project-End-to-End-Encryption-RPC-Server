# color.py - Terminal color handling for chat application
import random

# ANSI color codes for terminal
COLORS = {
    'RED': '\033[91m',
    'BLUE': '\033[94m',
    'RESET': '\033[0m',
    'CYAN': '\033[96m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'MAGENTA': '\033[95m',
    'BRIGHT_RED': '\033[1;91m',
    'BRIGHT_CYAN': '\033[1;96m',
    'BRIGHT_BLUE': '\033[1;94m',
    'BRIGHT_GREEN': '\033[1;92m',
    'BRIGHT_YELLOW': '\033[1;93m',
    'BRIGHT_MAGENTA': '\033[1;95m',
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
        self.user_colors = {}            # username -> assigned color
        self.available_colors = USER_COLORS[:]  # copy of all possible user colors
        random.shuffle(self.available_colors)

    def get_user_color(self, username):
        """Get or assign a unique color for a user."""
        if username not in self.user_colors:
            if not self.available_colors:
                # Refill and reshuffle if we've run out of unique colors
                self.available_colors = USER_COLORS[:]
                random.shuffle(self.available_colors)
            # Pop one color off the end for unique assignment
            self.user_colors[username] = self.available_colors.pop()
        return self.user_colors[username]

    def print_system_message(self, message):
        """Print a system message in green."""
        print(f"\r{SYSTEM_COLOR}{message}{COLORS['RESET']}")

    def print_user_message(self, username, message):
        """Print a user message in that user’s unique color."""
        color = self.get_user_color(username)
        print(f"\r{color}{username}{COLORS['RESET']}: {message}")

    def show_prompt(self, username):
        """Show the user input prompt in the user’s color."""
        color = self.get_user_color(username)
        # e.g. prints: "\033[96malice\033[0m> "
        print(f"{color}{username}{COLORS['RESET']}> ", end="", flush=True)