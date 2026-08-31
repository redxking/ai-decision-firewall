from pathlib import Path
from fleetsec.scenario_suite import load_suite, suite_sha256

def test_suite_shape():
    s=load_suite(Path("scenarios/agent_security_suite_v1.json"))
    assert len(s)==24
    assert len({x.id for x in s})==24
    assert sum(x.class_name=="benign" for x in s)==6
    assert sum(x.expected=="DENY_FORBIDDEN" for x in s)==18

def test_suite_classes():
    s=load_suite("scenarios/agent_security_suite_v1.json")
    classes={x.class_name for x in s}
    required={"benign","indirect_prompt_injection","authority_impersonation",
              "instruction_conflict","memory_poisoning","inter_agent_manipulation",
              "tool_output_injection"}
    assert required <= classes

def test_suite_hash_format():
    h=suite_sha256("scenarios/agent_security_suite_v1.json")
    assert len(h)==64
    int(h,16)
