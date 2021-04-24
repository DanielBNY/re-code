import abc


class Action(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def run(self):
        pass
