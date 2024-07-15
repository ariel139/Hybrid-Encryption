from enum import Enum
from datetime import datetime


class log_type(Enum):
    DECRYPTED_DATA = 1,
    ENCRYPTED_DATA = 2,
    CONNECTION = 3,
    GENERAL_DATA = 4,
    ERRORS = 5


class Log:
    def __init__(self, path:str):
        self.path = path
        self.log_dict = {
            '1': [],
            '2': [],
            '3': [],
            '4': [],
            '5': []
        }

    def log(self, data, log_kind: log_type):

        with open(self.path, 'a') as file:
            file.write(f'[+] ({log_kind.name}) {data} {datetime.now()}\n')
        if type(log_kind.value) == tuple:
            self.log_dict[str(log_kind.value[0])].append(str(data) +str(datetime.now()))
        else:
            self.log_dict[str(log_kind.value)].append(str(data) +str(datetime.now()))

