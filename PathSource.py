import os
import inspect
from pathlib import Path

MULTIPLE_DECOMPILED_FILES_DIRECTORY = "MultipleDecompiledFiles"
RECOVERED_CODE_DIRECTORY_NAME = "RecoveredCodeOutput"
RETDEC_DECOMPILER_FOLDER_NAME = "retdec"
FUNCTIONS_INFO_COLLECTION_NAME = "FunctionsInfo"
TEMPORARY_SAMPLE_DATA_DIRECTORY = ".SampleData"
FUNCTIONS_INFO_FILE_NAME = 'functions_info.json'
SAMPLES_DIR_NAME = "Samples"
ZIP_FILE_NAME = "RecoveredCodeBuild.zip"
OUT = "OUT"


def get_out_directory_path() -> str:
    return os.path.join(relative_path(), OUT)


def get_recovered_code_zip_path() -> str:
    return os.path.join(relative_path(), OUT, ZIP_FILE_NAME)


def get_file_to_analyze_directory_path() -> str:
    return os.path.join(relative_path(), SAMPLES_DIR_NAME)


def get_recovered_code_directory_path() -> str:
    return os.path.join(relative_path(), OUT, RECOVERED_CODE_DIRECTORY_NAME)


def get_temporary_sample_data_directory_path() -> str:
    return os.path.join(relative_path(), TEMPORARY_SAMPLE_DATA_DIRECTORY)


def get_decompiled_files_path() -> str:
    return os.path.join(get_temporary_sample_data_directory_path(), MULTIPLE_DECOMPILED_FILES_DIRECTORY)


def get_functions_info_file_path() -> str:
    return os.path.join(get_temporary_sample_data_directory_path(), FUNCTIONS_INFO_FILE_NAME)


def get_retdec_decompiler_path() -> str:
    return os.path.join(relative_path(), RETDEC_DECOMPILER_FOLDER_NAME, "bin", "retdec-decompiler.py")


def get_output_zip_directory_path() -> str:
    return os.path.join(get_recovered_code_directory_path())


def relative_path() -> str:
    return str(Path(os.path.abspath(inspect.getfile(relative_path))).parent.absolute())
