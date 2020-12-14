class FunctionInfo:
    def __init__(self, contained_address):
        """
        id: string
        contained_address: string
        file_id: string (id to hashes)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = f"function:{contained_address}"
        self.contained_address = contained_address
        self.file_id = f"file:{contained_address}"
        self.calls_out_set_id = f"function:{contained_address}:calls_out"
        self.calls_in_set_id = f"function:{contained_address}:calls_in"


class FileInfo:
    def __init__(self, contained_address):
        """
        id: string
        contained_address: string
        folder_id: string (id to hashes)
        contained_functions: string (set id)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = f"file:{contained_address}"
        self.contained_address = contained_address
        self.folder_id = f"folder:{contained_address}"
        self.contained_functions_set_id = f"file:{contained_address}:contained_functions"
        self.calls_out_set_id = f"file:{contained_address}:calls_out"
        self.calls_in_set_id = f"file:{contained_address}:calls_in"


class FolderInfo:
    def __init__(self, contained_address):
        """
        id: string
        contained_address: string
        contained_files: string (id to hashes)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = f"folder:{contained_address}"
        self.contained_address = contained_address
        self.contained_files_set_id = f"folder:{contained_address}:contained_files"
        self.calls_out_set_id = f"folder:{contained_address}:calls_out"
        self.calls_in_set_id = f"folder:{contained_address}:calls_in"
