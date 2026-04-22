import json
import logging
import re
import socket
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set
from urllib import request
from urllib.error import URLError

try:
    from ioc_finder import find_iocs
    from iocparser import IOCParser
except ImportError:
    find_iocs = None
    IOCParser = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TASK_PARAMETERS = {
    "T1": {"max_tokens": 1024, "top_p": 0.95, "temperature": 0.7, "top_k": 30},
    "T2": {"max_tokens": 50, "top_p": 0.95, "temperature": 0.7, "top_k": 30},
    "T3": {"max_tokens": 20, "top_p": 0.95, "temperature": 0.7, "top_k": 30},
    "T4": {"max_tokens": 20, "top_p": 0.95, "temperature": 0.7, "top_k": 30},
}

DEFAULT_T1_INSTRUCTION = (
    "Extract all STIX-compatible cyber threat entities from the CTI report and return only this format: "
    "<entities>Entity1|Entity2|...|EntityN</entities>"
)

DEFAULT_TASK_INSTRUCTIONS = {
    "T1": DEFAULT_T1_INSTRUCTION,
    "T2": (
        "Identify the most relevant STIX cyber threat entity type mentioned in the CTI report and return only this format: "
        "<entity_type>STIX_ENTITY_TYPE</entity_type>"
    ),
    "T3": (
        "Decide whether the report describes a direct relationship between the extracted cyber threat entities and the malicious activity. "
        "Return only this format: <related>YES or NO</related>"
    ),
    "T4": (
        "Choose the single best STIX relationship label for the report from this set: uses, communicates-with, downloads. "
        "Return only this format: <label>RELATIONSHIP_LABEL</label>"
    ),
}


def clean_paragraph(paragraph: str) -> str:
    if not isinstance(paragraph, str):
        return ""
    paragraph = paragraph.replace("[.]", ".")
    paragraph = paragraph.replace(".]", ".")
    paragraph = paragraph.replace("[:]", ":")
    paragraph = paragraph.replace("hxxps", "https")
    paragraph = paragraph.replace("hXXps", "https")
    paragraph = paragraph.replace("hXXp", "http")
    paragraph = paragraph.replace("hxxp", "http")
    paragraph = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', paragraph)
    paragraph = re.sub(r'\\u[0-9a-fA-F]{4}', '', paragraph)
    paragraph = paragraph.replace("aka ", "")
    paragraph = paragraph.replace("^", "")
    paragraph = paragraph.replace("|", "")
    return paragraph


def parse_response(response_text: str, task: str) -> Any:
    if not response_text:
        return "" if task != "T1" else []

    response_clean = response_text.split("---")[0].split("##")[0].strip()
    flags = re.DOTALL | re.IGNORECASE

    if task == "T1":
        match = re.search(r"<entities>(.*?)</entities>", response_clean, flags)
        if match:
            content = match.group(1).strip()
            return list(set([entity.strip() for entity in content.split("|") if entity.strip()]))
        logging.warning(f"T1 parsing failed for response snippet: {response_clean[:100]}...")
        return []

    if task == "T2":
        match = re.search(r"<entity_type>(.*?)</entity_type>", response_clean, flags)
        if match:
            return match.group(1).strip()
        logging.warning(f"T2 parsing failed for response snippet: {response_clean[:100]}...")
        return ""

    if task == "T3":
        match = re.search(r"<related>(.*?)</related>", response_clean, flags)
        if match:
            result = match.group(1).strip().upper()
            return result if result in ["YES", "NO"] else ""
        logging.warning(f"T3 parsing failed for response snippet: {response_clean[:100]}...")
        return ""

    if task == "T4":
        match = re.search(r"<label>(.*?)</label>", response_clean, flags)
        if match:
            return match.group(1).strip()
        logging.warning(f"T4 parsing failed for response snippet: {response_clean[:100]}...")
        return ""

    return response_clean


def get_iocs(text: str) -> Dict[str, List[str]]:
    iocs = defaultdict(list)

    if find_iocs is None or IOCParser is None:
        logging.warning("ioc-finder/iocparser not installed; skipping IOC enrichment.")
    else:
        try:
            raw_iocs = find_iocs(text)
            iocs["URL"].extend(raw_iocs.get("urls", []))
            iocs["EMAIL"].extend(raw_iocs.get("email_addresses", []))
            iocs["DOMAIN"].extend(raw_iocs.get("domains", []))
            iocs["IPv4"].extend(raw_iocs.get("ipv4s", []))
            iocs["IPv6"].extend(raw_iocs.get("ipv6s", []))
            iocs["FILE_HASH_SHA256"].extend(raw_iocs.get("sha256s", []))
            iocs["FILE_HASH_SHA1"].extend(raw_iocs.get("sha1s", []))
            iocs["FILE_HASH_MD5"].extend(raw_iocs.get("md5s", []))
            iocs["ASN"].extend(raw_iocs.get("asns", []))
            iocs["REGISTRY_KEY"].extend(raw_iocs.get("registry_key_paths", []))
            iocs["MAC_ADDRESS"].extend(raw_iocs.get("mac_addresses", []))
            iocs["FILE_PATH"].extend(raw_iocs.get("file_paths", []))
            for tactics in raw_iocs.get("attack_tactics", {}).values():
                iocs["MITRE_ATT&CK"].extend(tactics)
            for techniques in raw_iocs.get("attack_techniques", {}).values():
                iocs["MITRE_ATT&CK"].extend(techniques)
        except Exception as e:
            logging.error(f"Error during ioc_finder processing: {e}")

        try:
            text_obj = IOCParser(text)
            results = text_obj.parse()
            for result in results:
                if result.kind == "filename":
                    iocs["FILE_NAME"].append(result.value)
        except Exception as e:
            logging.error(f"Error during iocparser processing: {e}")

    try:
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        iocs["CVE"].extend(re.findall(cve_pattern, text, re.IGNORECASE))
        threat_actor_pattern = r"UNC[0-9]{4}|UAC-[0-9]{4}|\bTA\d{3}\b|APT[0-9]{1,2}"
        iocs["THREAT_ACTOR"].extend(re.findall(threat_actor_pattern, text))
    except Exception as e:
        logging.error(f"Error during custom regex matching: {e}")

    final_iocs = {}
    for key, values in iocs.items():
        final_iocs[key] = list(set(values))
    return final_iocs


def get_iocs_set(text: str) -> Set[str]:
    iocs_dict = get_iocs(text=text)
    set_iocs: Set[str] = set()
    for key in iocs_dict.keys():
        for element in iocs_dict[key]:
            set_iocs.add(str(element))
    return set_iocs


class ModelBackend:
    def complete(self, prompt: str, model_name: str, params: Dict[str, Any]) -> str:
        raise NotImplementedError


class OpenAICompatibleBackend(ModelBackend):
    def __init__(self, api_key: str = "dummy", base_url: str = "http://localhost:3216/v1"):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError("openai package is required when provider='openai'.") from exc
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def complete(self, prompt: str, model_name: str, params: Dict[str, Any]) -> str:
        response = self.client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=params.get("temperature", 0.7),
            max_tokens=params.get("max_tokens", 512),
            top_p=params.get("top_p", 0.95),
        )
        return response.choices[0].message.content or ""


class OllamaBackend(ModelBackend):
    def __init__(self, base_url: str = "http://10.50.28.25:11434", timeout_seconds: int = 60):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def complete(self, prompt: str, model_name: str, params: Dict[str, Any]) -> str:
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {
                "temperature": params.get("temperature", 0.7),
                "top_p": params.get("top_p", 0.95),
                "num_predict": params.get("max_tokens", 512),
                "num_ctx": 4096,
            },
        }
        req = request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data.get("message", {}).get("content", "") or ""
        except URLError as exc:
            raise RuntimeError(f"Failed to reach Ollama at {self.base_url}: {exc}") from exc
        except socket.timeout as exc:
            raise RuntimeError(
                f"Ollama request timed out at {self.base_url} after {self.timeout_seconds} seconds."
            ) from exc


def create_backend(
    provider: str = "ollama",
    api_key: str = "dummy",
    base_url: Optional[str] = None,
    timeout_seconds: int = 60,
) -> ModelBackend:
    provider_normalized = (provider or "ollama").strip().lower()
    if provider_normalized == "openai":
        return OpenAICompatibleBackend(api_key=api_key, base_url=base_url or "http://localhost:3216/v1")
    if provider_normalized == "ollama":
        return OllamaBackend(base_url=base_url or "http://localhost:11434", timeout_seconds=timeout_seconds)
    raise ValueError(f"Unsupported provider: {provider}. Use 'ollama' or 'openai'.")


def build_prompt(instruction: str, input_text: str) -> str:
    return f"Instruction: {instruction}\n\nInput: {clean_paragraph(input_text)}\n\nResponse:"


def run_task_prediction(
    backend: ModelBackend,
    input_text: str,
    model_name: str,
    task: str,
    instruction: Optional[str] = None,
) -> Dict[str, Any]:
    task_instruction = instruction or DEFAULT_TASK_INSTRUCTIONS.get(task, "")
    prompt = build_prompt(instruction=task_instruction, input_text=input_text)
    params = TASK_PARAMETERS.get(task, TASK_PARAMETERS["T1"])

    try:
        raw_prediction = backend.complete(prompt=prompt, model_name=model_name, params=params)
    except Exception as e:
        logging.warning(f"Model call failed for task {task} on input hash {hash(input_text)}: {e}")
        raw_prediction = ""

    return {
        "instruction": task_instruction,
        "raw_prediction": raw_prediction,
        "parsed_prediction": parse_response(raw_prediction, task),
    }


def post_process_t1_prediction(input_text: str, predicted_entities: List[str]) -> List[str]:
    external_iocs = get_iocs_set(text=input_text)
    predicted_labels = set()
    for item in predicted_entities:
        if item and item in input_text:
            predicted_labels.add(item)
    return list(predicted_labels.union(external_iocs))


def normalize_relationship_label(label: str, input_text: str = "") -> str:
    normalized = (label or "").strip().lower().replace("_", "-")
    if normalized in {"use", "uses"}:
        return "uses"
    if normalized in {"communicates-with", "beacons-to", "exfiltrates-to"}:
        return "communicates-with"
    if normalized in {"downloads", "drops"}:
        return "downloads"

    input_lower = (input_text or "").lower()
    if any(token in input_lower for token in ["download", "drop", "copy", "transfer", "retrieve"]):
        return "downloads"
    if any(token in input_lower for token in ["beacon", "communicat", "exfiltrat"]):
        return "communicates-with"
    if normalized:
        return "uses"
    return ""


def build_stix_output(
    entities: List[str],
    entity_type: str,
    related: str,
    relationship_label: str,
    input_text: str = "",
) -> Dict[str, Any]:
    related_normalized = (related or "").strip().upper()
    relationship_label_normalized = normalize_relationship_label(relationship_label, input_text=input_text)

    relationships: List[Dict[str, Any]] = []
    if related_normalized == "YES" and relationship_label_normalized:
        relationships.append(
            {
                "label": relationship_label_normalized,
                "related": True,
            }
        )

    return {
        "entities": entities,
        "entity_type": entity_type,
        "relationships": relationships,
        "related": related_normalized == "YES",
        "relationship_label": relationship_label_normalized,
    }


def extract_stix_from_report(
    report_text: str,
    model_name: str,
    provider: str = "ollama",
    base_url: Optional[str] = None,
    api_key: str = "dummy",
    timeout_seconds: int = 60,
    instruction: str = DEFAULT_T1_INSTRUCTION,
) -> Dict[str, Any]:
    backend = create_backend(
        provider=provider,
        api_key=api_key,
        base_url=base_url,
        timeout_seconds=timeout_seconds,
    )
    cleaned_input = clean_paragraph(report_text)
    task_results = {}
    for task in ("T1", "T2", "T3", "T4"):
        task_results[task] = run_task_prediction(
            backend=backend,
            input_text=cleaned_input,
            model_name=model_name,
            task=task,
            instruction=instruction if task == "T1" else None,
        )

    parsed_entities = task_results["T1"]["parsed_prediction"]
    final_stix_entities = post_process_t1_prediction(cleaned_input, parsed_entities)

    stix_output = build_stix_output(
        entities=final_stix_entities,
        entity_type=task_results["T2"]["parsed_prediction"],
        related=task_results["T3"]["parsed_prediction"],
        relationship_label=task_results["T4"]["parsed_prediction"],
        input_text=cleaned_input,
    )

    return {
        "input": cleaned_input,
        "raw_prediction": task_results["T1"]["raw_prediction"],
        "stix_entities": parsed_entities,
        "final_stix_entities": final_stix_entities,
        "stix_output": stix_output,
    }
