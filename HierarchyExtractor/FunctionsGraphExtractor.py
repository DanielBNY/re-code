from Models import FunctionModel
from BinaryExtractor import BinaryExtractor


class FunctionsGraphExtractor:
    """
    Functions call graph - functions are nodes and edges are calls to other functions
    """

    def __init__(self, binary_extractor_session: BinaryExtractor, redis_session):
        """
        The class contain the connection between functions and the list of functions addresses
        :param binary_extractor_session
        :param redis_session
        """
        self.all_functions_info = binary_extractor_session.get_all_functions_info()
        self.redis_session = redis_session

    def run(self):
        """
        Extract the functions call graph to redis, saves the nodes and the edges between them
        """
        self.save_functions_graph()
        self.save_functions_edges()

    def save_functions_graph(self):
        for function in self.all_functions_info:
            fnc_address = function['offset']
            fnc_repo_actions = FunctionModel(address=str(fnc_address).encode(), redis_session=self.redis_session)
            fnc_repo_actions.recursion_init(str(function['realsz']).encode())

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
                        fnc_repo_actions = FunctionModel(address=str(source_function).encode(),
                                                         redis_session=self.redis_session)
                        fnc_repo_actions.add_function_edge(str(called_function).encode())
