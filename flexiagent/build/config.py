import os
import json

current_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)))

class DotNotationDict:
    def __init__(self, dictionary):
        for key, value in dictionary.items():
            if isinstance(value, dict):
                # Recursively convert nested dictionaries
                value = DotNotationDict(value)
            setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

class Config:
    def __init__(self, config_file=f'{current_dir}/config.json'):
        self._config_file = config_file
        self._config = {}

        self._load()

    def _load(self):
        with open(self._config_file, 'r', encoding='utf-8') as config_file:
            self._config = DotNotationDict(json.load(config_file))

    def __getattr__(self, key):
        try:
            return self._config[key]
        except KeyError:
            return None

    def __getitem__(self, key):
        try:
            return self._config[key]
        except KeyError:
            return None

config = Config()
