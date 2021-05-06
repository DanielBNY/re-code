import re
import redis


class FunctionDetector:
    def __init__(self, redis_session: redis.Redis):
        self.function_code = ""
        self.functions_lines = 0
        self.redis_session = redis_session
        self.function_address = None
        self.currently_analyzing_function = False
        self.finished_analyzing_function = False
        self.wrapped_function_name = None
        self.empty_function = False

    def reset_values(self):
        self.function_code = ""
        self.functions_lines = 0
        self.function_address = None
        self.wrapped_function_name = None

    def analyze_code_line(self, code_line):
        if self.finished_analyzing_function:
            # If finished to analyze a function and analyzing a new line reset the values of the last function
            self.reset_values()
        function_address = self.get_function_address(line=code_line)
        if function_address:
            self.reset_values()
            self.function_address = function_address
            self.currently_analyzing_function = True
            self.finished_analyzing_function = False

        if self.currently_analyzing_function:
            self.functions_lines += 1
            self.function_code += code_line

        if self.is_end_of_function(code_line):
            self.currently_analyzing_function = False
            self.finished_analyzing_function = True
            self.set_wrapped_function_name()
            self.empty_function = self.is_empty_function()

    def is_function_detected(self):
        if self.finished_analyzing_function and self.function_code:
            return self

    def set_wrapped_function_name(self):
        function_line_list = self.function_code.split('\n')
        last_line = None
        if len(function_line_list) <= 6:
            for function_line in reversed(function_line_list):
                if last_line == '}':
                    regex_match = re.search(r'(\w+)\(', function_line)
                    if regex_match:
                        wrapped_function_name = regex_match.group(1)
                        self.wrapped_function_name = wrapped_function_name
                last_line = function_line

    def is_empty_function(self):
        """
        Example of an empty function:

        int64_t function_1d1f0(void) {
            // 0x1d1f0
            int64_t result; // 0x1d1f0
            return result;
        }
        """
        function_line_list = self.function_code.split('\n')
        if len(function_line_list) < 8:
            last_line = ""
            for function_line in reversed(function_line_list):
                if last_line == '}':
                    if "return result;" not in function_line:
                        return False
                if "return result;" in last_line:
                    if "int64_t result;" not in function_line:
                        return False
                last_line = function_line
            return True
        else:
            return False

    @staticmethod
    def is_end_of_function(line):
        return line[0] == '}'

    @staticmethod
    def get_function_address(line):
        detected_regex = re.search(r'// Address range: (\S+)', line)
        if detected_regex:
            return int(detected_regex.group(1), 16)
