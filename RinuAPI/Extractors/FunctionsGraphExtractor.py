from BinaryExtractor import BinaryAnalysis
from models import FunctionNode, FunctionEdge


class FunctionsGraph:

    def __init__(self, all_functions_info):
        """
        The class contain the connection between functions and the list of functions addresses
        :param all_functions_info: list
        """
        self.all_functions_info = all_functions_info

    def save_functions_graph(self):
        for function in self.all_functions_info:
            new_function_node = FunctionNode(function['offset'])
            new_function_node.save()

    def get_valid_function_address(self, address):
        """
        Return the valid function address or None if the address is not a function
        The function is used because some function references are 4-bit behind the exact function address
        :param address: function address
        :return: int or None
        """
        if address in FunctionNode:
            return address
        elif address + 4 in FunctionNode:
            return address + 4
        return None

    def get_functions_edges(self, all_functions_info):
        """
        Return the edges between functions
        Their is a validation for the call references because
        not all call references are pointing to functions
        :return: list, function edges
        """
        for function_info in all_functions_info:
            if 'callrefs' in function_info:
                for call_reference in function_info['callrefs']:
                    function_address = self.get_valid_function_address(call_reference['addr'])
                    if function_address and call_reference['type'] == 'CALL':
                        function_edge = FunctionEdge(function_info['offset'], function_address)
                        function_edge.save()


bin_analysis = BinaryAnalysis('/bin/ls')
all_functions_info = bin_analysis.get_all_functions_info()
function_graph = FunctionsGraph(all_functions_info)
function_graph.save_functions_graph()
