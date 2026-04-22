import json
import logging
import re
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


def clean_paragraph(paragraph: str) -> str:
    if not isinstance(paragraph, str):
        return ""
    paragraph = paragraph.encode("utf-8").decode()
    paragraph = paragraph.replace("[.]", ".")
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
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url.rstrip("/")

    def complete(self, prompt: str, model_name: str, params: Dict[str, Any]) -> str:
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {
                "temperature": params.get("temperature", 0.7),
                "top_p": params.get("top_p", 0.95),
                "num_predict": params.get("max_tokens", 512),
            },
        }
        req = request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data.get("message", {}).get("content", "") or ""
        except URLError as exc:
            raise RuntimeError(f"Failed to reach Ollama at {self.base_url}: {exc}") from exc
        except TimeoutError as exc:
            raise RuntimeError(f"Ollama request timed out at {self.base_url}.") from exc


def create_backend(provider: str = "ollama", api_key: str = "dummy", base_url: Optional[str] = None) -> ModelBackend:
    provider_normalized = (provider or "ollama").strip().lower()
    if provider_normalized == "openai":
        return OpenAICompatibleBackend(api_key=api_key, base_url=base_url or "http://localhost:3216/v1")
    if provider_normalized == "ollama":
        return OllamaBackend(base_url=base_url or "http://localhost:11434")
    raise ValueError(f"Unsupported provider: {provider}. Use 'ollama' or 'openai'.")


def build_prompt(instruction: str, input_text: str) -> str:
    return f"Instruction: {instruction}\n\nInput: {clean_paragraph(input_text)}\n\nResponse:"


def post_process_t1_prediction(input_text: str, predicted_entities: List[str]) -> List[str]:
    external_iocs = get_iocs_set(text=input_text)
    predicted_labels = set()
    for item in predicted_entities:
        if item and item in input_text:
            predicted_labels.add(item)
    return list(predicted_labels.union(external_iocs))


def extract_stix_from_report(
    report_text: str,
    model_name: str,
    provider: str = "ollama",
    base_url: Optional[str] = None,
    api_key: str = "dummy",
    instruction: str = DEFAULT_T1_INSTRUCTION,
) -> Dict[str, Any]:
    backend = create_backend(provider=provider, api_key=api_key, base_url=base_url)
    cleaned_input = clean_paragraph(report_text)
    prompt = build_prompt(instruction=instruction, input_text=cleaned_input)
    params = TASK_PARAMETERS["T1"]

    try:
        raw_prediction = backend.complete(prompt=prompt, model_name=model_name, params=params)
    except Exception as e:
        logging.warning(f"Model call failed for input hash {hash(report_text)}: {e}")
        raw_prediction = ""

    parsed_entities = parse_response(raw_prediction, "T1")
    final_stix_entities = post_process_t1_prediction(cleaned_input, parsed_entities)

    return {
        "input": cleaned_input,
        "raw_prediction": raw_prediction,
        "stix_entities": parsed_entities,
        "final_stix_entities": final_stix_entities,
    }
