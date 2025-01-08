import os
import configparser

# Automatically load configuration
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.ini")

def load_config():
    """Load and return the configuration parser."""
    config_parser = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config_parser.read(CONFIG_PATH)
    else:
        raise FileNotFoundError(f"Configuration file not found at {CONFIG_PATH}")
    return config_parser

# Expose the loaded configuration to be imported elsewhere
config = load_config()
