import logging
import os
import yaml
import math
from collections import Counter

def setup_logging(config_path="config/config.yaml"):
    """Configures the logging module based on config.yaml."""
    
    # Default config
    log_level = logging.INFO
    log_file = "logs/app.log"
    
    # Try to load config
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            level_str = config.get('logging', {}).get('level', 'INFO')
            log_level = getattr(logging, level_str.upper(), logging.INFO)
            log_file = config.get('logging', {}).get('file', 'logs/app.log')
    except Exception as e:
        print(f"Error loading config for logging: {e}")

    # Create logs directory if not exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logging.info("Logging initialized.")

def load_config(config_path="config/config.yaml"):
    """Loads the configuration file."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return {}

def calculate_entropy(text):
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy
