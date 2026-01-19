import json
import os
import logging

logger = logging.getLogger(__name__)

class SettingsManager:
    def __init__(self, filename="settings.json"):
        self.filename = filename
        self.settings = {
            "interface": None,
            "scan_interval": 30,
            "paranoid_mode": False,
            "domain_log_limit": 20
        }
        self.load()

    def load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    data = json.load(f)
                    self.settings.update(data)
                logger.info(f"Loaded settings from {self.filename}")
            except Exception as e:
                logger.error(f"Failed to load settings: {e}")

    def save(self):
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.settings, f, indent=2)
            logger.info("Settings saved")
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")

    def get(self, key, default=None):
        return self.settings.get(key, default)

    def set(self, key, value):
        self.settings[key] = value
        self.save()

    def update(self, new_settings):
        self.settings.update(new_settings)
        self.save()
