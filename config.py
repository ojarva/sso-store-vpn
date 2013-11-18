import json

class Config:
    def __init__(self):
        self.c = {
                  "redis-db": 0,
                  "redis-port": 6379,
                  "redis-hostname": "localhost"
                 }
        self.local_settings = {}
        try:
            self.local_settings = json.load(open("local_settings.json"))
        except (IOError, EOFError):
            pass
        self.c.update(self.local_settings)

    def get(self, key):
        return self.c.get(key)

    def set(self, key, data):
        self.local_settings[key] = data
        json.dump(self.local_settings, open("local_settings.json", "w"))
