import os


class ExportRetdecData:
    def __init__(self):
        pass

    def export_retdec_data(self, decompiler_path, decompiled_file_path, binary_path):
        stream = os.popen(f"{decompiler_path} -o {decompiled_file_path} {binary_path}")
        output = stream.read()
        return output
