import json
import os
import argparse
import re
import logging
from datetime import datetime
from typing import Dict, Any, List

from tqdm import tqdm

from azerg_pipeline import (
    TASK_PARAMETERS,
    clean_paragraph,
    parse_response,
    get_iocs_set,
    create_backend,
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_dataset(file_path: str) -> List[Dict[str, Any]]:
    """Loads dataset from a JSON file."""
    logging.info(f"Loading dataset from {file_path}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Input JSON format error: expected a list of objects.")
        logging.info(f"Successfully loaded {len(data)} examples.")
        return data
    except FileNotFoundError:
        logging.error(f"Dataset file not found: {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error loading dataset: {e}")
        return []

def run_inference(backend: Any, data: List[Dict[str, Any]], task: str, model_name: str) -> List[Dict[str, Any]]:
    """Runs inference on the dataset and parses responses."""
    results = []
    params = TASK_PARAMETERS.get(task, {})
    
    for item in tqdm(data, desc=f"Processing Task {task}"):
        instruction = item.get("instruction", "")
        input_text = item.get("input", "")
        gold_output = item.get("output", "") # Ground truth

        # Clean input before sending to model
        cleaned_input = clean_paragraph(input_text)
        
        # Format prompt
        prompt = f"Instruction: {instruction}\n\nInput: {cleaned_input}\n\nResponse:"

        try:
            raw_prediction = backend.complete(prompt=prompt, model_name=model_name, params=params)
        except Exception as e:
            logging.warning(f"API call failed for input hash {hash(input_text)}: {e}")
            raw_prediction = ""

        parsed_prediction = parse_response(raw_prediction, task)

        results.append({
            "instruction": instruction,
            "input": cleaned_input,
            "gold": gold_output,
            "raw_prediction": raw_prediction,
            "predicted": parsed_prediction,
        })
    return results

def post_process_t1_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Applies T1 specific post-processing: IOC enrichment and filtering."""
    logging.info("Applying Task T1 post-processing logic...")
    processed_results = []
    for result in tqdm(results, desc="Post-processing T1"):
        input_text = result["input"]
        
        external_iocs = get_iocs_set(text=input_text)

        gold_list = parse_response(result["gold"], "T1")
        gold_labels = set()
        for item in gold_list:
            if item and item in input_text:
                gold_labels.add(item)

        predicted_labels = set()
        for item in result["predicted"]:
            if item and item in input_text:
                predicted_labels.add(item)

        final_gold_set = gold_labels.union(external_iocs)
        final_predicted_set = predicted_labels.union(external_iocs)

        result["gold"] = list(final_gold_set)
        result["predicted"] = list(final_predicted_set)
        processed_results.append(result)
        
    return processed_results

def save_results(results: List[Dict[str, Any]], task: str, dataset_name: str, model_name: str):
    """Saves results to a JSON file."""
    sanitized_model_name = re.sub(r'[\\/]', '_', model_name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"./results/{task}"
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{dataset_name}__{task}__{sanitized_model_name}__{timestamp}.json"
    output_path = os.path.join(output_dir, filename)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    logging.info(f"Results saved successfully to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Run inference for AZERG tasks with Ollama or OpenAI-compatible backends.")
    parser.add_argument("--task", type=str, required=True, choices=["T1", "T2", "T3", "T4"], help="Task identifier.")
    parser.add_argument("--dataset", type=str, required=True, choices=["azerg", "annoctr"], help="Dataset name prefix.")
    parser.add_argument("--model_name", type=str, default="QCRI/AZERG-MixTask-Mistral", help="Name of the model to use.")
    parser.add_argument("--api_key", type=str, default="dummy", help="OpenAI API key.")
    parser.add_argument("--provider", type=str, default="ollama", choices=["ollama", "openai"], help="Model provider.")
    parser.add_argument("--base_url", type=str, default=None, help="Provider URL. Defaults: Ollama=http://localhost:11434, OpenAI-compatible=http://localhost:3216/v1.")
    args = parser.parse_args()

    # Load data
    dataset_path = f"./AZERG-Dataset/test/{args.dataset}_{args.task}_test.json"
    data_to_process = load_dataset(dataset_path)
    if not data_to_process:
        return

    # Initialize model backend
    backend = create_backend(provider=args.provider, api_key=args.api_key, base_url=args.base_url)

    # Run inference
    inference_results = run_inference(backend, data_to_process, args.task, args.model_name)

    # Apply task-specific post-processing
    if args.task == "T1":
        final_results = post_process_t1_results(inference_results)
    else:
        final_results = inference_results

    # Save results
    save_results(final_results, args.task, args.dataset, args.model_name)

if __name__ == "__main__":
    main()
