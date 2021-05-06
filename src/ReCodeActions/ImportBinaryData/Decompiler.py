import os
import subprocess

from src.AbstractClasses import Action


class Decompiler(Action):
    def __init__(self, number_of_processes: int, decompiled_files_path: str, analyzed_file: str,
                 start_virtual_address: int, end_virtual_address: int, decompiler_path: str):
        self.number_of_processes = number_of_processes
        self.decompiled_files_path = decompiled_files_path
        self.analyzed_file = analyzed_file
        self.start_virtual_address = start_virtual_address
        self.end_virtual_address = end_virtual_address
        self.decompiler_path = decompiler_path

    def run(self):
        file_size = os.stat(self.analyzed_file).st_size
        decompilers_processes = []
        start_address = self.start_virtual_address
        while start_address < self.end_virtual_address:
            analyzed_chunks_size = self.calculate_analyzed_chunks_size(file_size)
            decompiler_process = subprocess.Popen(["python", self.decompiler_path, "--select-ranges",
                                                   f"{hex(start_address)}-{hex(start_address + analyzed_chunks_size)}",
                                                   "-o",
                                                   f"{self.decompiled_files_path + '/file' + str(start_address)}.c",
                                                   self.analyzed_file,
                                                   "--cleanup", "--select-decode-only"])
            decompilers_processes.append(decompiler_process)
            if len(decompilers_processes) == self.number_of_processes:
                decompilers_processes[0].communicate()
                del decompilers_processes[0]
            start_address += analyzed_chunks_size

        for last_decompiler_process in decompilers_processes:
            last_decompiler_process.communicate()

    def calculate_analyzed_chunks_size(self, file_size) -> int:
        divided_file_chunk = int(file_size / (self.number_of_processes * 2))
        return divided_file_chunk
