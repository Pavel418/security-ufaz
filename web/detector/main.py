import os
import json
from tqdm import tqdm
from openai import APITimeoutError

from utils.prompt_loader import (
    load_config,
    get_prompts,
)
from utils.io import read_all_text_files, write_multiple_outputs
from pipelines.pipeline import run_pipeline
from llm_clients.openai_client import OpenAIClient

def main():
    config_path = "detector/config.yaml"
    config = load_config(config_path)

    prompts = get_prompts(config)

    ds = config.get("dataset")
    if not isinstance(ds, dict):
        raise ValueError("Config error: `dataset` must be a single object with input_path, output_path.")

    dataset_name = ds.get("name", "dataset")
    input_dir = ds.get("input_path")
    output_dir = ds.get("output_path")

    if not input_dir or not output_dir:
        raise ValueError("Config error: `dataset` requires `input_path`, and `output_path`.")

    llm_client = OpenAIClient()

    input_files = read_all_text_files(input_dir)
    pbar = tqdm(total=len(input_files))
    pbar.set_description(f"{dataset_name}")

    for name, input_text in input_files.items():
        pbar.set_description(f"Processing: {name}")

        # Input JSON parsing
        try:
            parsed = json.loads(input_text)
        except json.JSONDecodeError:
            pbar.write(f"[WARN] {name}: not valid JSON, skipping.")
            pbar.update()
            continue

        # --------- PIPELINE ---------
        save_file_path = os.path.join(output_dir, f"pipeline")
        os.makedirs(save_file_path, exist_ok=True)

        # Resume if file exists
        exist_msg = None
        existing_file = os.path.join(save_file_path, f"{name}.txt")
        if os.path.exists(existing_file):
            try:
                with open(existing_file, "r", encoding="utf-8") as infile:
                    exist_msg = json.load(infile)
            except Exception:
                exist_msg = None

        # Run with retry-on-timeout
        while True:
            try:
                output_obj = run_pipeline(
                    llm_client,
                    json.dumps(parsed),
                    prompts,
                    pbar=pbar,
                    exist_msg=exist_msg,
                )
                break
            except APITimeoutError as e:
                output_obj = {}
                pbar.write(f"Timeout error: {e}. Retrying...")

        write_multiple_outputs(
            save_file_path,
            {name: json.dumps(output_obj, ensure_ascii=False, indent=2)},
        )
        pbar.update()


if __name__ == "__main__":
    main()