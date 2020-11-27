class FunctionsGraph:

    def __init__(self, all_function_addresses, all_functions_info):
        """
        The class contain the connection between functions and the list of functions addresses
        :param all_function_addresses: dictionary
        :param all_functions_info: list
        """
        self.all_function_addresses = all_function_addresses
        self.function_edges = self.get_functions_edges(all_functions_info)

    def get_valid_function_address(self, address):
        """
        Return the valid function address or None if the address is not a function
        The function is used because some function references are 4-bit behind the exact function address
        :param address: function address
        :return: int\None
        """
        if address in self.all_function_addresses:
            return address
        elif address + 4 in self.all_function_addresses:
            return address + 4
        return None

    def get_functions_edges(self, all_functions_info):
        """
        Return the edges between functions
        Their is a validation for the call references because
        not all call references are pointing to functions
        :return: list, function edges
        """
        functions_edges = []
        for function_info in all_functions_info:
            if 'callrefs' in function_info:
                for call_reference in function_info['callrefs']:
                    function_address = self.get_valid_function_address(call_reference['addr'])
                    if function_address and call_reference['type'] == 'CALL':
                        functions_edges.append((function_info['offset'], function_address))
        return functions_edges
