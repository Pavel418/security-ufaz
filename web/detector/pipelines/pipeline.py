import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from ..utils.mitre_info import get_mitre_info

# ---------- JSON utilities (robust) ----------
# remove non-printable control chars except \t \n \r
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F]')

def _sanitize_json_text(s: str) -> str:
    if not isinstance(s, str):
        return ""
    s = _CONTROL_CHARS_RE.sub("", s)
    # fix common fence patterns: {"\nresults": ...} -> {"results": ...}
    s = re.sub(r'^\{\s*"\s*\n\s*(results"\s*:)', r'{"\1', s)
    s = re.sub(r'^\{\s*"\s+(results"\s*:)',   r'{"\1', s)
    s = re.sub(r'^\{\s*(results"\s*:)',       r'{"\1', s)  # { results": ...} -> {"results": ...}
    return s.strip()

def extract_json(text: str) -> Dict[str, Any]:
    """
    Always returns a dict. Default: {"results": []}
    Order of attempts:
      1) fenced ```json ... ```
      2) smallest {...} containing "results"
      3) whole text
    Accepts raw lists and wraps to {"results": [...]}
    """
    DEFAULT = {"results": []}
    if not isinstance(text, str) or not text.strip():
        return DEFAULT

    # 1) fenced json
    m = re.search(r"```json\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    candidate = m.group(1) if m else None

    # 2) object containing "results"
    if candidate is None:
        idx = text.find('"results"')
        if idx == -1:
            idx = text.lower().find('results')
        if idx != -1:
            start = text.rfind('{', 0, idx)
            if start != -1:
                depth = 0
                end_balanced = None
                for i, ch in enumerate(text[start:], start=start):
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            end_balanced = i
                            break
                if end_balanced is not None:
                    candidate = text[start:end_balanced+1]

    # 3) last resort: full text
    if candidate is None:
        candidate = text

    s = _sanitize_json_text(candidate)
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        return DEFAULT

    if isinstance(obj, list):
        return {"results": obj}
    if isinstance(obj, dict):
        # normalize missing results key
        if "results" not in obj:
            obj["results"] = obj.get("results", [])
        return obj
    return DEFAULT

# Backward-compatible alias for older imports
def get_json_from_text(text: str) -> Dict[str, Any]:
    return extract_json(text)

# ---------- Message helpers ----------
def _mk_message(system_prompt: str, user_prompt: str, input_text: str) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"{user_prompt}\n\n{input_text}"},
    ]

def _resolve_prompt_keys(method_name: str) -> Tuple[str, str]:
    """
    Keep OLD naming as reference:
      method_name == ""         => exp_key='module2_expert',          sc_key='module2_expert_sc'
      method_name == '_scoring' => exp_key='module2_expert_scoring',  sc_key='module2_expert_sc'
    """
    if method_name == "_scoring":
        return "module2_expert_scoring", "module2_expert_sc"
    return "module2_expert", "module2_expert_sc"

# ---------- Parallel fan-out ----------
def _parallel_call_from_messages(
    llm_client,
    message: List[Dict[str, str]],
    run_times: int,
    max_workers: int = 5,
) -> Tuple[List[str], int, int]:
    answers: List[str] = []
    in_tok = out_tok = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(llm_client.call_from_messages, message) for _ in range(run_times)]
        for future in as_completed(futures):
            result, it, ot = future.result()
            answers.append(result)
            in_tok += it
            out_tok += ot
    return answers, in_tok, out_tok

# ---------- Core ----------
def consistency_expert(llm_client, input_text, prompt_pair, method_name: str = "", run_times: int = 3):
    exp_key, sc_key = _resolve_prompt_keys(method_name)

    answer_list = [{"role": "system", "content": prompt_pair[sc_key]["system"]}]
    answers: List[str] = []
    total_in = total_out = 0

    futures = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for area, tactics in prompt_pair[exp_key]["experts"].items():
            msg = _mk_message(
                prompt_pair[exp_key]["system"].format(area=area, tactics=tactics),
                prompt_pair[exp_key]["user"],
                input_text,
            )
            for _ in range(run_times):
                futures.append(executor.submit(llm_client.call_from_messages, msg))

        for future in as_completed(futures):
            result, itkn, otkn = future.result()
            total_in += itkn
            total_out += otkn
            answers.append(result)
            answer_list.append({"role": "assistant", "content": result})

    # Collect candidates (flatten lists; ignore junk)
    candidates: List[Dict[str, Any]] = []
    for raw in answers:
        parsed = extract_json(raw)
        if isinstance(parsed.get("results"), list):
            candidates.extend(parsed["results"])
        elif isinstance(parsed, list):
            candidates.extend(parsed)

    # Synthesis/score step (scorer)
    answer_list.append({
        "role": "user",
        "content": (
            f"{prompt_pair[sc_key]['user']}\n\n{input_text}\n\n"
            f"# Possible Techniques\n\n{json.dumps(candidates, ensure_ascii=False)}"
        ),
    })
    final_answer, itkn, otkn = llm_client.call_from_messages(messages=answer_list)
    total_in += itkn
    total_out += otkn
    return final_answer, answers, total_in, total_out

def consistency_multi_times(llm_client, input_text, prompt_pair, run_times: int = 3):
    answer_list = [{"role": "system", "content": prompt_pair["module2_expert_sc"]["system"]}]
    msg = _mk_message(prompt_pair["module2_original"]["system"], prompt_pair["module2_original"]["user"], input_text)
    answers, total_in, total_out = _parallel_call_from_messages(llm_client, msg, run_times)

    for r in answers:
        answer_list.append({"role": "assistant", "content": r})

    counts: Dict[str, Dict[str, Any]] = {}
    for r in answers:
        parsed = extract_json(r)
        for item in parsed.get("results", []):
            root = str(item.get("technique_id", "")).split(".")[0]
            if not root:
                continue
            if root not in counts:
                counts[root] = {**item, "count": 1}
            else:
                counts[root]["count"] += 1

    sorted_result = sorted(counts.values(), key=lambda x: x["count"], reverse=True)
    return sorted_result[:5], answers, total_in, total_out

def consistency_multi_times_diff(llm_client, input_text, prompt_pair, run_times: int = 3):
    answers: List[str] = []
    total_in = total_out = 0

    msg = _mk_message(prompt_pair["module2_original"]["system"], prompt_pair["module2_original"]["user"], input_text)
    round0, itkn, otkn = llm_client.call_from_messages(msg)
    total_in += itkn
    total_out += otkn
    answers.append(round0)

    answer_json = extract_json(round0).get("results", [])
    if not isinstance(answer_json, list):
        answer_json = []

    for _ in range(run_times):
        excluded_tts = [
            {
                "technique_id": i.get("technique_id", ""),
                "technique_name": i.get("technique_name", ""),
                "tactic_name": i.get("tactic_name", ""),
            } for i in answer_json
        ]
        excluded_prompt = (
            "**Important constraint**: Do not include or consider the following techniques in your mapping:"
            + json.dumps(excluded_tts, ensure_ascii=False)
        )
        msg = _mk_message(
            prompt_pair["module2_original"]["system"],
            prompt_pair["module2_original"]["user"],
            f"{input_text}\n\n{excluded_prompt}",
        )
        ans, itkn, otkn = llm_client.call_from_messages(msg)
        total_in += itkn
        total_out += otkn
        answers.append(ans)

        existed_roots = {str(i.get("technique_id", "")).split(".")[0] for i in answer_json}
        parsed = extract_json(ans)
        for item in parsed.get("results", []):
            root = str(item.get("technique_id", "")).split(".")[0]
            if root and root not in existed_roots:
                answer_json.append(item)

    return answer_json, answers, total_in, total_out

def self_debate(llm_client, input_text, prompt_pair, max_debate_times: int = 3):
    total_in = total_out = 0
    answers: List[str] = []

    init_msg = _mk_message(prompt_pair["module2_original"]["system"], prompt_pair["module2_original"]["user"], input_text)
    first_ans, itkn, otkn = llm_client.call_from_messages(init_msg)
    total_in += itkn
    total_out += otkn

    final_json: List[Dict[str, Any]] = []
    debate_result = ""

    for _ in range(max_debate_times):
        debate_info = ""
        first_mapping_info = ""
        if answers:
            debate_info = "\n\n# Critic's analysis：\n\n" + "\n\n".join(
                f"## Debate round #{i+1}：\n\n{a}" for i, a in enumerate(answers)
            )
        else:
            first_mapping_info = f"\n\n# Original analysis and mapping result：\n\n{first_ans}"

        msg = _mk_message(
            prompt_pair["module2_critic"]["system"],
            prompt_pair["module2_critic"]["user"],
            f"# Network information\n\n{input_text}{first_mapping_info}{debate_info}",
        )
        debate_result, itkn, otkn = llm_client.call_from_messages(msg)
        answers.append(debate_result)
        total_in += itkn
        total_out += otkn

        result_json = extract_json(debate_result).get("results", [])
        result_set = {(i.get("technique_id"), i.get("tactic_name")) for i in result_json}
        final_set = {(i.get("technique_id"), i.get("tactic_name")) for i in (final_json or [])}

        if result_set == final_set:
            break
        final_json = result_json or []

    answers.insert(0, first_ans)
    return final_json, answers, total_in, total_out

def convert_to_json(llm_client, input_text, prompt_pair, pbar=None, max_retries: int = 3):
    if pbar:
        pbar.set_description("Running Step 2 converting")

    in_t = out_t = 0
    last_text = input_text
    for attempt in range(1, max_retries + 1):
        try:
            json_text, add_in, add_out = _call_llm_json(
                llm_client, input_text=last_text, prompt_pair=prompt_pair["converter"]
            )
            in_t += add_in
            out_t += add_out

            parsed = extract_json(json_text)
            if "results" in parsed and isinstance(parsed["results"], list):
                # drop optional fields; step 3 will recompute/normalize
                for item in parsed["results"]:
                    if isinstance(item, dict):
                        item.pop("relevance", None)
                        item.pop("impact", None)
                return parsed["results"], in_t, out_t
        except Exception:
            pass

        if pbar:
            pbar.set_description(f"Running Step 2 reconverting (attempt {attempt+1})")

    # fallback empty
    return [], in_t, out_t

def run_pipeline(llm_client, input_text: str, prompts: dict, pbar=None, exist_msg=None) -> dict:
    if exist_msg and exist_msg.get("step_3", {}).get("input"):
        return exist_msg

    base_desc = pbar.desc if pbar else ""

    # Step 1
    if pbar: pbar.set_description(f"{base_desc}Running Step 1")
    step_1_input = input_text
    ts = time.time()
    step1, s1_in, s1_out = _call_llm(llm_client, input_text=step_1_input, prompt=prompts["module1"], use_system_prompt=True)
    step_1_duration = time.time() - ts

    # Step 2
    ts = time.time()
    if pbar: pbar.set_description(f"{base_desc}Running Step 2")
    step2, step2_answers, s2_in, s2_out = consistency_expert(
        llm_client=llm_client,
        input_text=f"{step_1_input}\n\n{step1}",
        prompt_pair=prompts,
        run_times=1,
        method_name="_scoring",
    )
    step_2_json_dict = extract_json(step2)
    step_2_json = step_2_json_dict.get("results", [])
    if not step_2_json:
        step_2_json, add_in, add_out = convert_to_json(llm_client=llm_client, input_text=step2, prompt_pair=prompts, pbar=pbar)
        s2_in += add_in
        s2_out += add_out
    step_2_duration = time.time() - ts

    # Step 3
    if pbar: pbar.set_description(f"{base_desc}Running Step 3")
    ttp_definitions = check_answer(step_2_json)
    ts = time.time()
    step_3_messages = _mk_message(
        prompts["module3"]["system"],
        prompts["module3"]["user"],
        (
            f"# Original Logs\n\n{step_1_input}\n\n"
            f"# Network environment and anomaly\n\n{step1}\n\n"
            f"# mapping analysis\n\n{step2}\n\n"
            f"# TT results and ATT&CK official definitions\n\n{ttp_definitions}"
        ),
    )
    step_3_input = step_3_messages[1]["content"]
    step3, s3_in, s3_out = llm_client.call_from_messages(messages=step_3_messages)

    # robust parse with converter fallback loop
    mapping_result = extract_json(step3).get("results", [])
    if not mapping_result:
        # try converter a few times
        for _ in range(3):
            mapping_text, c_in, c_out = _call_llm_json(llm_client, input_text=step3, prompt_pair=prompts["converter"])
            s3_in += c_in
            s3_out += c_out
            mapping_result = extract_json(mapping_text).get("results", [])
            if mapping_result:
                break

    step_3_duration = time.time() - ts

    # Normalize relevance/impact + score
    for item in mapping_result:
        if isinstance(item, dict):
            item["relevance"] = float(item.get("relevance", 0.0) or 0.0)
            item["impact"]   = float(item.get("impact",   0.0) or 0.0)
            item["score"]    = item["relevance"] + item["impact"]
    try:
        mapping_result = sorted(mapping_result, key=lambda x: x.get("score", 0.0), reverse=True)
    except Exception:
        pass

    result = {
        "step_1": {
            "input": step_1_input,
            "output": step1,
            "duration": round(step_1_duration, 2),
            "tokens": {"input": s1_in, "output": s1_out},
        },
        "step_2": {
            "input": f"{step_1_input}\n\n{step1}",
            "consistency": step2_answers,
            "output": step2,
            "json": step_2_json,
            "duration": round(step_2_duration, 2),
            "tokens": {"input": s2_in, "output": s2_out},
        },
        "step_3": {
            "input": step_3_input,
            "output": step3,
            "duration": round(step_3_duration, 2),
            "tokens": {"input": s3_in, "output": s3_out},
        },
        "final_answer": mapping_result,
    }
    return result

# ---------- Checks ----------
def check_answer(answer_dict: List[Dict[str, Any]]):
    correct_info = []
    for result_item in answer_dict:
        tech_id = result_item.get("technique_id")
        if not tech_id:
            result_item["error"] = "The mapping procedure is not complete, ignore this item."
            correct_info.append(result_item); continue
        tactic_name = str(result_item.get("tactic_name", "")).lower().strip()
        gt = get_mitre_info(tech_id=tech_id)
        if gt is None:
            result_item["error"] = f"tech_id {tech_id} not found in mitre framework."
        else:
            if tactic_name not in gt["tactics"]:
                result_item["error"] = (
                    f"tactic name {tactic_name} not match technique {tech_id}， "
                    f"the tactic name should be one of {gt['tactics']}."
                )
            result_item["description"] = gt["description"]
        correct_info.append(result_item)
    return correct_info

def _call_llm(llm_client, input_text: str, prompt: Dict[str, str], use_system_prompt: bool) -> Tuple[str, int, int]:
    user_content = f"{prompt.get('user', '')}\n\n{input_text}"
    messages = (
        [{"role": "system", "content": prompt.get("system", "")}, {"role": "user", "content": user_content}]
        if use_system_prompt else [{"role": "user", "content": user_content}]
    )
    return llm_client.call_from_messages(messages)

def _call_llm_json(llm_client, input_text: str, prompt_pair: Dict[str, str]) -> Tuple[str, int, int]:
    system_prompt = prompt_pair.get("system", "")
    user_prompt = prompt_pair.get("user", "")
    messages = [
        {"role": "assistant", "content": input_text},
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    return llm_client.call_from_messages(messages)
