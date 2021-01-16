import json
import requests

URL = 'http://localhost:5000/'


class BinaryExtractor:
    """
    This class consist of functionality and initialization
    required by for binary analysis
    """

    def __init__(self, binary_path):
        """

        :param binary_path: string, binary path
        """

        response = requests.post(URL + "init/", json={'path': binary_path})
        if response.status_code != 201:
            raise Exception(response.text)

    @staticmethod
    def get_radare_functions_addresses():
        """
        Set the redis set with id 'r2_functions_addresses' to the radare2 detected functions addresses
        """
        response = requests.get(URL + "r2_functions_addresses/")
        if response.status_code != 200:
            raise Exception(response.text)

    @staticmethod
    def jmp_to_address(address):
        response = requests.post(URL + "command/" + 's 0x' + hex(address))
        if response.status_code != 200:
            raise Exception(response.text)

    @staticmethod
    def jmp_to_main():
        response = requests.post(URL + "command/" + 's main')
        if response.status_code != 200:
            raise Exception(response.text)

    @staticmethod
    def get_current_address():
        response = requests.post(URL + "command/" + 's')
        if response.status_code != 200:
            raise Exception(response.text)
        return int(response.text, 16)

    def get_main_address(self):
        self.jmp_to_main()
        return self.get_current_address()

    @staticmethod
    def get_all_functions_info(target_file):
        response = requests.get(URL + "functions_info_extractor/", json={'path': target_file})
        if response.status_code != 200:
            raise Exception(response.text)
        return response.text[:-1]  # remove \n at the end of the string

    @staticmethod
    def decompile_function(function_offset):
        """
        :return: string, c like code in text
        """
        response = requests.get(URL + "decompile_function/" + function_offset)
        if response.status_code != 200:
            raise Exception(response.text)
        decompiled_function_lines = response.text.split('\n')
        decompiled_text = ""
        for line in decompiled_function_lines:
            if line:
                if "/" != line[0] and "#" != line[0] and "\n" != line[0]:
                    decompiled_text += line + "\n"
        return decompiled_text

    def disassemble_function(self, function_offset):
        """
        :return: dictionary, assembly function code
        """
        self.jmp_to_address(function_offset)
        response = requests.post(URL + "command/" + 'pdfj')
        if response.status_code != 200:
            raise Exception(response.text)
        disassemble = json.loads(response.text)
        # pdj - disassemble to json
        return disassemble

    @staticmethod
    def get_sections():
        response = requests.post(URL + "command/" + 'iSj')
        if response.status_code != 200:
            raise Exception(response.text)
        sections = json.loads(response.text)
        return sections

    @staticmethod
    def analyze_function_in_address(address):
        response = requests.post(URL + f"analyze_function_address/{address}")
        if response.status_code != 200:
            raise Exception(response.text)
