import os

def read_all_text_files(folder_path: str) -> dict:
    data = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".txt"):
            full_path = os.path.join(folder_path, filename)
            with open(full_path, "r", encoding="utf-8") as f:
                file_key = os.path.splitext(filename)[0]
                data[file_key] = f.read()
    return data

def write_output(file_path: str, content: str):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

def write_multiple_outputs(output_dir: str, results: dict, prefix: str):
    os.makedirs(output_dir, exist_ok=True)
    file_paths = []
    for name, content in results.items():
        file_name = f"{prefix}_{name}.txt"
        file_path = os.path.join(output_dir, file_name)
        file_paths.append(file_path)
        write_output(file_path, content)
    return file_paths