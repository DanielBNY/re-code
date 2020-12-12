from BinaryExtractor import BinaryAnalysis
from RepoActions import FunctionRepoActions
import re
import redis

REDIS_SERVER_IP = "localhost"


class FunctionsGraph:

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

    @staticmethod
    def save_sections(sections):
        """
        The function saves the sections information to the database
        """
        current_session = extractor_session()
        for index, section in enumerate(sections):
            physical_end_address = section['paddr'] + section['size']
            virtual_end_address = section['vaddr'] + section['vsize']
            permission_read = bool(re.search('.*r.*', section['perm']))
            permission_write = bool(re.search('.*w.*', section['perm']))
            permission_execute = bool(re.search('.*x.*', section['perm']))
            file_section = FileSection(number=index, name=section['name'], physical_start_address=section['paddr'],
                                       physical_end_address=physical_end_address,
                                       virtual_start_address=section['vaddr'],
                                       virtual_end_address=virtual_end_address, permission_read=permission_read,
                                       permission_write=permission_write, permission_execute=permission_execute)
            current_session.add(file_section)
            current_session.commit()
        current_session.close()
