import re
import pytoml


class Config(dict):
    """ Config utility class
    """
    DEFAULT = {
        'rpc': {
            'laddr', 'tcp://127.0.0.1:26657'
        },
        'ca': {
            'ca_key_file': None,
            'allow_templates': ['CA', 'Node', 'User'],
            'ca_valid_for': '795d',
            'host_valid_for': '530d',
            'user_valid_for': '365d',
            'waiting_for_downstream': '300s'
        }
    }

    def __init__(self, config_toml):
        with open(config_toml, 'r') as file:
            data = pytoml.load(file)
        super().__init__(data)

    def __getitem__(self, key):
        data = super().__getitem__(key)
        if isinstance(data, dict):
            if key in self.DEFAULT:
                data = {**self.DEFAULT, **dict((key, value) for key, value in data.items())}
            return self.normalize(data)

    @staticmethod
    def normalize(item):
        def normalize_value(value):
            if isinstance(value, str):
                if match := re.search(r'(\d+)s', value):
                    value = float(match.group(1))
                elif match := re.search(r'(\d+)ms', value):
                    value = float(match.group(1)) / 1000
                elif match := re.search(r'(\d+)d', value):
                    value = int(match.group(1))
            return value

        if isinstance(item, dict):
            return dict((key, normalize_value(value)) for key, value in item.items())
        elif isinstance(item, list):
            return [normalize_value(value) for value in item]
        else:
            return normalize_value(item)
