import os


def decompile_to_file(decompiler_path, decompiled_file_path, binary_path):
    stream = os.popen(f"{decompiler_path} -o {decompiled_file_path} {binary_path}")
    output = stream.read()
    return output
