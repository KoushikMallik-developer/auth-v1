from abc import ABC


class AUTHBaseException(ABC, Exception):
    def __init__(self, msg: str):
        if msg:
            self.msg = msg
