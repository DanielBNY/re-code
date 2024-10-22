import os
import subprocess
from typing import List

from src.ReCodeActions.AbstractClasses import Action


class MultiProcessedDecompilation(Action):
    def __init__(self, number_of_processes: int, decompiled_files_path: str, analyzed_file: str,
                 start_virtual_address: int, end_virtual_address: int, decompiler_path: str):
        self.number_of_processes = number_of_processes
        self.decompiled_files_path = decompiled_files_path
        self.analyzed_file = analyzed_file
        self.start_virtual_address = start_virtual_address
        self.end_virtual_address = end_virtual_address
        self.decompiler_path = decompiler_path
        self.decompilers_processes: List[subprocess.Popen] = []

    def run(self):
        file_size = os.stat(self.analyzed_file).st_size
        analyzed_chunks_size = self.calculate_analyzed_chunks_size(file_size)
        for chunk_start_address in range(self.start_virtual_address, self.end_virtual_address, analyzed_chunks_size):
            chunk_end_address = self.calculate_end_address(chunk_start_address, analyzed_chunks_size)
            decompiler_process = self.open_decompiler_process(chunk_start_address, chunk_end_address)
            self.decompilers_processes.append(decompiler_process)
            is_max_process_number = len(self.decompilers_processes) == self.number_of_processes
            if is_max_process_number:
                self.wait_last_process_terminated()

        self.wait_decompiler_processes_terminated()

    def calculate_analyzed_chunks_size(self, file_size) -> int:
        divided_file_chunk = int(file_size / (self.number_of_processes * 2))
        return divided_file_chunk

    def wait_decompiler_processes_terminated(self):
        for last_decompiler_process in self.decompilers_processes:
            last_decompiler_process.communicate()

    def calculate_end_address(self, start, analyzed_chunks_size):
        end_address = start + analyzed_chunks_size
        if self.end_virtual_address < start + analyzed_chunks_size:
            end_address = self.end_virtual_address
        return end_address

    def open_decompiler_process(self, chunk_start_address, chunk_end_address):
        decompiler_process = subprocess.Popen(["python", self.decompiler_path, "--select-ranges",
                                               f"{hex(chunk_start_address)}-{hex(chunk_end_address)}",
                                               "-o",
                                               f"{self.decompiled_files_path + '/file' + str(chunk_start_address)}.c",
                                               self.analyzed_file,
                                               "--cleanup", "--select-decode-only"])
        return decompiler_process

    def wait_last_process_terminated(self):
        self.decompilers_processes[0].communicate()
        del self.decompilers_processes[0]
