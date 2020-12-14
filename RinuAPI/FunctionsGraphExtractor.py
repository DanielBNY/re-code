from BinaryExtractor import BinaryAnalysis
from RepoActions import FunctionRepoActions
import redis

REDIS_SERVER_IP = "localhost"


class FunctionsGraphExtractor:

    def __init__(self, all_functions_info):
        """
        The class contain the connection between functions and the list of functions addresses
        :param all_functions_info: list
        """
        self.all_functions_info = all_functions_info
        self.redis_session = redis.Redis(REDIS_SERVER_IP)

    def save_functions_graph(self):
        for function in self.all_functions_info:
            fnc_address = function['offset']
            fnc_repo_actions = FunctionRepoActions(address=fnc_address, redis_session=self.redis_session)
            fnc_repo_actions.recursion_init(function['realsz'])

    def get_valid_function_address(self, address):
        """
        Return the valid function address or None if the address is not a function
        The function is used because some function references are 4-bit behind the exact function address
        :param address: function address
        :return: int or None
        """

        if self.redis_session.exists(f"function:{address}"):
            return address
        elif self.redis_session.exists(f"function:{int(address) + 4}"):
            return address + 4
        return None

    def save_functions_edges(self):
        """
        save the edges between functions
        Their is a validation for the call references because
        not all call references are pointing to functions
        :return: list, function edges
        """
        for function_info in self.all_functions_info:
            if 'callrefs' in function_info:
                for call_reference in function_info['callrefs']:
                    called_function = self.get_valid_function_address(call_reference['addr'])
                    if called_function and call_reference['type'] == 'CALL':
                        source_function = function_info['offset']
                        fnc_repo_actions = FunctionRepoActions(address=source_function,
                                                               redis_session=self.redis_session)
                        fnc_repo_actions.add_edge(called_function)

