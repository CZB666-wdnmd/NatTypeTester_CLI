#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NAT Network Behavior AI Evaluator
==================================
NAT网络行为AI评估工具

读取 NatTypeTester CLI 输出的 JSON 测试结果，严格按照设定的 RFC 评分体系
计算每个测试项的"标准度"和"开放度"分数，并调用 OpenAI 兼容 API 流式生成
AI 综合评估报告（附带控制台实时 Markdown 格式化）。

用法:
    python nat_evaluator.py <test1.json> [test2.json ...]
           [--server URL] [--key API_KEY] [--model MODEL]
           [--output OUTPUT.txt] [--no-ai] [--prompt-file prompt.md]
"""

import json
import os
import sys
import io
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Callable
import urllib.request
import urllib.error

# 修复 Windows 控制台中文编码问题，并激活 ANSI 转义序列支持
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    os.system("")  # 激活 Windows 10+ 终端的 ANSI 颜色支持

# ============================================================
# 配置区 -- 在此修改 API 服务器地址、密钥和模型 (支持通过传参覆盖)
# ============================================================
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "")

SCRIPT_DIR = Path(__file__).resolve().parent
PROMPT_FILE = SCRIPT_DIR / "prompt.md"
# ============================================================

# ===========================================================
# 数据类型定义
# ============================================================
@dataclass
class TestItemScore:
    name: str
    rfc: str
    result: str
    standardness: int
    openness: int

@dataclass
class ProtocolScores:
    udp_standardness: int = 0
    udp_openness: int = 0
    tcp_standardness: int = 0
    tcp_openness: int = 0
    icmp_standardness: int = 0
    icmp_openness: int = 0
    cross_standardness: int = 0
    cross_openness: int = 0
    total_standardness: int = 0
    total_openness: int = 0
    items: List[TestItemScore] = field(default_factory=list)

TestItemDef = Tuple[str, Callable, str, str, Tuple[int, int]]


# ============================================================
# 辅助函数与核心评分逻辑
# ============================================================
def to_bool(val: Any) -> bool:
    if isinstance(val, bool): return val
    if isinstance(val, str): return val.lower() in ("true", "pass", "success")
    return False

def score_nattype(val: Any) -> Tuple[int, int]:
    v = str(val).lower()
    if "fullcone" in v: return (3, 3)
    if "portrestrictedcone" in v: return (2, 1)
    if "restrictedcone" in v: return (2, 2)
    if "symmetric" in v: return (1, 0)
    return (0, 0)

def score_mapping(val: Any) -> Tuple[int, int]:
    v = str(val).lower()
    if "endpointindependent" in v: return (3, 3)
    if "addressandportdependent" in v: return (2, 1)
    if "addressdependent" in v: return (2, 2)
    return (0, 0)

def score_filtering(val: Any) -> Tuple[int, int]:
    v = str(val).lower()
    if "endpointindependent" in v: return (3, 3)
    if "addressandportdependent" in v: return (2, 1)
    if "addressdependent" in v: return (2, 2)
    return (0, 0)

def score_eim_eif(val: Any) -> Tuple[int, int]: return (1, 0) if to_bool(val) else (0, 1)
def score_port_rand(val: Any) -> Tuple[int, int]: return (1, 0) if to_bool(val) else (0, 1)
def score_alloc(val: Any) -> Tuple[int, int]: return (1, 2) if "sequential" in str(val).lower() else (1, 0)
def score_ipv4_id(val: Any) -> Tuple[int, int]: return (0, 1) if to_bool(val) else (1, 0)
def score_hairpin(val: Any) -> Tuple[int, int]: return (2, 2) if to_bool(val) else (0, 0)
def score_hairpin_src(val: Any) -> Tuple[int, int]: return (1, 1) if to_bool(val) else (0, 0)
def score_port_range(val: Any) -> Tuple[int, int]: return (1, 1) if to_bool(val) else (0, 0)
def score_port_parity(val: Any) -> Tuple[int, int]: return (0, 1) if to_bool(val) else (1, 0)
def score_port_overload(val: Any) -> Tuple[int, int]: return (0, 0) if to_bool(val) else (1, 1)
def score_binding(val: Any) -> Tuple[int, int]: return (1, 1) if to_bool(val) else (0, 0)
def score_tcp_simopen(val: Any) -> Tuple[int, int]: return (2, 2) if to_bool(val) else (0, 0)
def score_unexpected_syn(val: Any) -> Tuple[int, int]: return (1, 1) if to_bool(val) else (0, 0)
def score_basic_feature(val: Any) -> Tuple[int, int]: return (1, 1) if to_bool(val) else (0, 0)
def score_icmp_payload(val: Any) -> Tuple[int, int]: return (1, 0) if to_bool(val) else (0, 1)
def score_malformed(val: Any) -> Tuple[int, int]: return (0, 1) if to_bool(val) else (1, 0)

RFC3489_ITEMS: List[TestItemDef] = [("NatType", score_nattype, "基础NAT类型", "cross", (3, 3))]
RFC5780_ITEMS: List[TestItemDef] = [
    ("BindingTest",       score_binding,   "绑定测试",     "cross", (1, 1)),
    ("MappingBehavior",   score_mapping,   "UDP映射行为",  "udp",   (3, 3)),
    ("FilteringBehavior", score_filtering, "UDP过滤行为",  "udp",   (3, 3)),
]
RFC4787_ITEMS: List[TestItemDef] = [
    ("BindingTest",                    score_binding,       "绑定测试",            "cross", (1, 1)),
    ("MappingBehavior",                score_mapping,       "UDP映射行为",         "udp",   (3, 3)),
    ("FilteringBehavior",              score_filtering,     "UDP过滤行为",         "udp",   (3, 3)),
    ("PortRangePreservation",          score_port_range,    "端口范围保持",        "udp",   (1, 1)),
    ("PortParityPreservation",         score_port_parity,   "端口奇偶性保持",      "udp",   (1, 1)),
    ("IcmpErrorHandling",              score_basic_feature, "ICMP错误转发(UDP)",   "udp",   (1, 1)),
    ("UdpHairpinning",                 score_hairpin,       "UDP发夹通信",         "udp",   (2, 2)),
    ("UdpHairpinningSourceAddress",    score_hairpin_src,   "UDP发夹源地址校验",   "udp",   (1, 1)),
    ("OutboundFragmentation",          score_basic_feature, "出站IP分片",          "udp",   (1, 1)),
    ("OutboundDfFragmentationError",   score_basic_feature, "DF分片超MTU报错",     "udp",   (1, 1)),
    ("InboundFragmentation",           score_basic_feature, "入站IP分片",          "udp",   (1, 1)),
    ("OutOfOrderFragmentation",        score_basic_feature, "乱序IP分片重组",      "udp",   (1, 1)),
    ("DeterminismMappingConsistent",   score_basic_feature, "映射一致性(确定性)",  "udp",   (1, 1)),
    ("DeterminismFilteringConsistent", score_basic_feature, "过滤一致性(确定性)",  "udp",   (1, 1)),
    ("DeterminismPortRangeConsistent", score_basic_feature, "端口范围确定性",      "udp",   (1, 1)),
    ("DeterminismPortParityConsistent",score_basic_feature, "端口奇偶确定性",      "udp",   (1, 1)),
    ("PortOverloading",                score_port_overload, "端口重载(超载)检查",  "udp",   (1, 1)),
]
RFC5382_ITEMS: List[TestItemDef] = [
    ("MappingBehavior",            score_mapping,        "TCP映射行为",         "tcp", (3, 3)),
    ("FilteringBehavior",          score_filtering,      "TCP过滤行为",         "tcp", (3, 3)),
    ("TcpSimultaneousOpen",        score_tcp_simopen,    "TCP同时打开(握手)",   "tcp", (2, 2)),
    ("UnexpectedSynHandling",      score_unexpected_syn, "意外SYN静默处理",     "tcp", (1, 1)),
    ("IcmpErrorHandling",          score_basic_feature,  "ICMP错误转发(TCP)",   "tcp", (1, 1)),
    ("TcpHairpinning",             score_hairpin,        "TCP发夹通信",         "tcp", (2, 2)),
    ("TcpHairpinningSourceAddress",score_hairpin_src,    "TCP发夹源地址校验",   "tcp", (1, 1)),
]
RFC5508_ITEMS: List[TestItemDef] = [
    ("MappingBehavior",                         score_mapping,        "ICMP映射行为",            "icmp", (3, 3)),
    ("FilteringBehavior",                       score_filtering,      "ICMP过滤行为",            "icmp", (3, 3)),
    ("IcmpErrorPayloadValidation",              score_icmp_payload,   "ICMP错误负载严格校验",    "icmp", (1, 1)),
    ("MalformedSrvBadOuterChecksumForwarded",   score_malformed,      "Srv外部Checksum错误转发", "icmp", (1, 1)),
    ("MalformedSrvBadInnerIpChecksumForwarded", score_malformed,      "Srv内层IP Checksum转发",  "icmp", (1, 1)),
    ("MalformedSrvBadUdpChecksumForwarded",     score_malformed,      "Srv内层UDP Checksum转发", "icmp", (1, 1)),
    ("MalformedCliBadOuterChecksumForwarded",   score_malformed,      "Cli外部Checksum错误转发", "icmp", (1, 1)),
    ("MalformedCliBadInnerIpChecksumForwarded", score_malformed,      "Cli内层IP Checksum转发",  "icmp", (1, 1)),
    ("MalformedCliBadUdpChecksumForwarded",     score_malformed,      "Cli内层UDP Checksum转发", "icmp", (1, 1)),
    ("OutboundIcmpError",                       score_basic_feature,  "出站ICMP报错",            "icmp", (1, 1)),
    ("IcmpHairpinningQuery",                    score_hairpin,        "ICMP发夹Query",           "icmp", (2, 2)),
    ("IcmpHairpinningError",                    score_hairpin,        "ICMP发夹Error",           "icmp", (2, 2)),
]
RFC7857_ITEMS: List[TestItemDef] = [
    ("UdpMappingBehavior",      score_mapping,       "UDP映射行为",          "udp",   (3, 3)),
    ("UdpFilteringBehavior",    score_filtering,     "UDP过滤行为",          "udp",   (3, 3)),
    ("TcpFilteringBehavior",    score_filtering,     "TCP过滤行为",          "tcp",   (3, 3)),
    ("EimProtocolIndependence", score_eim_eif,       "EIM协议独立性",        "cross", (1, 1)),
    ("EifProtocolIndependence", score_eim_eif,       "EIF协议独立性",        "cross", (1, 1)),
    ("PortParityPreservation",  score_port_parity,   "端口奇偶保持(降级)",   "cross", (1, 1)),
    ("UdpHairpinning",          score_hairpin,       "UDP发夹通信",          "udp",   (2, 2)),
    ("TcpHairpinning",          score_hairpin,       "TCP发夹通信",          "tcp",   (2, 2)),
    ("IcmpHairpinning",         score_hairpin,       "ICMP发夹通信",         "icmp",  (2, 2)),
    ("PortRandomization",       score_port_rand,     "公网端口随机化分配",   "cross", (1, 1)),
    ("AllocationBehavior",      score_alloc,         "端口分配序列行为",     "cross", (1, 2)),
    ("Ipv4IdPreservation",      score_ipv4_id,       "IPv4 ID原样保留",      "cross", (1, 1)),
]

def score_single_rfc(rfc_name: str, data: dict) -> ProtocolScores:
    result = ProtocolScores()
    rfc_items_map = {
        "rfc3489": RFC3489_ITEMS, "rfc5780": RFC5780_ITEMS,
        "rfc4787": RFC4787_ITEMS, "rfc5382": RFC5382_ITEMS,
        "rfc5508": RFC5508_ITEMS, "rfc7857": RFC7857_ITEMS,
    }
    items = rfc_items_map.get(rfc_name.lower(), [])
    for json_key, score_func, display_name, protocol, _ in items:
        if json_key not in data or data[json_key] is None: continue
        val_str = str(data[json_key])
        if val_str in ("Unknown", "Inconclusive", "-", "null", ""): continue
        s, o = score_func(data[json_key])
        result.items.append(TestItemScore(f"[{rfc_name.upper()}] {display_name}", rfc_name, val_str, s, o))
        
        if protocol == "udp": result.udp_standardness += s; result.udp_openness += o
        elif protocol == "tcp": result.tcp_standardness += s; result.tcp_openness += o
        elif protocol == "icmp": result.icmp_standardness += s; result.icmp_openness += o
        elif protocol == "cross": result.cross_standardness += s; result.cross_openness += o

    result.total_standardness = result.udp_standardness + result.tcp_standardness + result.icmp_standardness + result.cross_standardness
    result.total_openness = result.udp_openness + result.tcp_openness + result.icmp_openness + result.cross_openness
    return result

def merge_scores(all_scores: List[ProtocolScores]) -> ProtocolScores:
    merged = ProtocolScores()
    for s in all_scores:
        for attr in ["udp_standardness", "udp_openness", "tcp_standardness", "tcp_openness", 
                     "icmp_standardness", "icmp_openness", "cross_standardness", "cross_openness", 
                     "total_standardness", "total_openness"]:
            setattr(merged, attr, getattr(merged, attr) + getattr(s, attr))
        merged.items.extend(s.items)
    return merged

def calc_max_possible(used_rfcs: List[str]) -> ProtocolScores:
    result = ProtocolScores()
    rfc_items_map = {
        "rfc3489": RFC3489_ITEMS, "rfc5780": RFC5780_ITEMS,
        "rfc4787": RFC4787_ITEMS, "rfc5382": RFC5382_ITEMS,
        "rfc5508": RFC5508_ITEMS, "rfc7857": RFC7857_ITEMS,
    }
    for rfc in used_rfcs:
        for _, _, _, protocol, (max_s, max_o) in rfc_items_map.get(rfc.lower(), []):
            if protocol == "udp": result.udp_standardness += max_s; result.udp_openness += max_o
            elif protocol == "tcp": result.tcp_standardness += max_s; result.tcp_openness += max_o
            elif protocol == "icmp": result.icmp_standardness += max_s; result.icmp_openness += max_o
            elif protocol == "cross": result.cross_standardness += max_s; result.cross_openness += max_o
    result.total_standardness = result.udp_standardness + result.tcp_standardness + result.icmp_standardness + result.cross_standardness
    result.total_openness = result.udp_openness + result.tcp_openness + result.icmp_openness + result.cross_openness
    return result

def normalize_score(actual: int, maximum: int) -> float:
    return round(actual / maximum * 100, 1) if maximum > 0 else 0.0

def format_score_report(all_scores: List[ProtocolScores], max_scores: ProtocolScores, used_rfcs: List[str]) -> str:
    merged = merge_scores(all_scores)
    lines = ["=" * 72, "  NAT 网络行为评分报告 (严格基于 IETF RFC)", "=" * 72, ""]
    for rfc_name in used_rfcs:
        rfc_items = [it for it in merged.items if it.rfc.lower() == rfc_name.lower()]
        if not rfc_items: continue
        lines.append(f"--- {rfc_name.upper()} 测试项 ---")
        for it in rfc_items:
            lines.append(f"  {it.name:<32s} 结果={it.result:<26s} 标准={it.standardness:2d}  开放={it.openness:2d}")
        lines.append("")

    lines.extend(["-" * 72, "  按协议汇总", "-" * 72])
    rows = [
        ("UDP", merged.udp_standardness, merged.udp_openness, max_scores.udp_standardness, max_scores.udp_openness),
        ("TCP", merged.tcp_standardness, merged.tcp_openness, max_scores.tcp_standardness, max_scores.tcp_openness),
        ("ICMP", merged.icmp_standardness, merged.icmp_openness, max_scores.icmp_standardness, max_scores.icmp_openness),
        ("Cross", merged.cross_standardness, merged.cross_openness, max_scores.cross_standardness, max_scores.cross_openness),
    ]
    for lbl, as_, ao_, ms_, mo_ in rows:
        lines.append(f"  {lbl:<8s} 标准度: {as_:3d}/{ms_:<3d} ({normalize_score(as_, ms_):5.1f}%)  |  开放度: {ao_:3d}/{mo_:<3d} ({normalize_score(ao_, mo_):5.1f}%)")

    lines.extend(["", "-" * 72, "  综合总体评分", "-" * 72])
    lines.append(f"  ★ 标准度总分: {merged.total_standardness}/{max_scores.total_standardness} ({normalize_score(merged.total_standardness, max_scores.total_standardness)}%)")
    lines.append(f"  ★ 开放度总分: {merged.total_openness}/{max_scores.total_openness} ({normalize_score(merged.total_openness, max_scores.total_openness)}%)")
    lines.append("=" * 72)
    return "\n".join(lines)


# ============================================================
# 控制台流式 Markdown 解析器 (零依赖)
# ============================================================
class MarkdownStreamFormatter:
    """单遍流式状态机：在字符逐个到来时解析 Markdown 并注入 ANSI 颜色代码"""
    def __init__(self):
        self.in_bold = False
        self.star_buf = 0
        self.is_header = False
        self.at_start = True

    def feed(self, chunk: str) -> str:
        out = ""
        for char in chunk:
            if char == '\n':
                if self.is_header:
                    out += "\033[0m" # 换行时清除标题的高亮
                    self.is_header = False
                out += char
                self.at_start = True
                self.star_buf = 0
                continue

            if char == '*':
                self.star_buf += 1
                if self.star_buf == 2:
                    self.in_bold = not self.in_bold
                    out += "\033[1m\033[93m" if self.in_bold else "\033[0m" # 黄色粗体
                    if not self.in_bold and self.is_header:
                        out += "\033[96m\033[1m" # 若退出加粗且在标题行内，恢复青色
                    self.star_buf = 0
                continue
            else:
                if self.star_buf == 1:
                    out += '*'
                    self.star_buf = 0
                elif self.star_buf > 1:
                    self.star_buf = 0
                    
            if self.at_start:
                if char == '#':
                    self.is_header = True
                    out += "\033[96m\033[1m#" # 标题标记为青色粗体
                    continue
                elif char != ' ':
                    self.at_start = False
                    
            if char == '|':
                out += "\033[35m|\033[0m" # 表格分割线为紫色
                if self.is_header:
                    out += "\033[96m\033[1m"
                elif self.in_bold:
                    out += "\033[1m\033[93m"
                continue
                
            out += char
        return out


def stream_openai_api(system_prompt: str, user_content: str, base_url: str, api_key: str, model: str):
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.7,
        "max_tokens": 4096,
        "stream": True
    }
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for line in resp:
                line_str = line.decode('utf-8').strip()
                if not line_str or not line_str.startswith("data: "):
                    continue
                content = line_str[6:]
                if content == "[DONE]":
                    break
                try:
                    chunk = json.loads(content)
                    delta = chunk['choices'][0].get('delta', {})
                    content_val = delta.get('content')
                    # 修复关键点：仅在 content_val 存在(且非None)时才 yield
                    if content_val is not None:
                        yield content_val
                except Exception:
                    pass
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        yield f"\n\n[API 错误 HTTP {e.code}]\n{body}"
    except Exception as e:
        yield f"\n\n[请求错误] {type(e).__name__}: {e}"


def main():
    parser = argparse.ArgumentParser(description="NAT网络行为流式AI评估工具")
    parser.add_argument("json_files", nargs="+", help="JSON测试结果文件")
    parser.add_argument("--server", default=OPENAI_BASE_URL, help="OpenAI兼容API地址")
    parser.add_argument("--key", default=OPENAI_API_KEY, help="API密钥")
    parser.add_argument("--model", default=OPENAI_MODEL, help="模型名称")
    parser.add_argument("--output", "-o", default=None, help="保存评估报告至文件")
    parser.add_argument("--no-ai", action="store_true", help="跳过AI调用")
    parser.add_argument("--prompt-file", default=None, help="自定义提示词路径")
    args = parser.parse_args()

    prompt_path = Path(args.prompt_file) if args.prompt_file else PROMPT_FILE
    system_prompt = prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else "请根据评分分析NAT状态并总结。"
    
    all_scores, all_json_data, used_rfcs = [], {}, set()

    for filepath in args.json_files:
        if not os.path.isfile(filepath):
            print(f"[错误] 文件不存在: {filepath}"); sys.exit(1)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        rfc_name = data.get("rfc", "").lower()
        if rfc_name:
            used_rfcs.add(rfc_name)
            all_json_data[filepath] = data
            all_scores.append(score_single_rfc(rfc_name, data))

    if not all_scores:
        print("[错误] 没有有效的测试数据"); sys.exit(1)

    used_rfcs = sorted(list(used_rfcs))
    max_scores = calc_max_possible(used_rfcs)
    score_report = format_score_report(all_scores, max_scores, used_rfcs)
    print(score_report)
    print()

    if args.no_ai:
        if args.output: Path(args.output).write_text(score_report, encoding="utf-8")
        return

    user_parts = [
        "以下是 NAT 行为测试的精准算分结果和原始 JSON 数据，请根据该结果进行综合评估：\n",
        score_report,
        "\n--- 原始测试 JSON 数据 ---\n",
    ]
    for filepath, data in all_json_data.items():
        user_parts.append(f"\n/// 文件: {filepath}\n{json.dumps(data, ensure_ascii=False, indent=2)}")

    print("=" * 72)
    print("  AI 实时流式评估 (Markdown解析开启)")
    print("=" * 72)
    
    full_ai_response = []
    md_formatter = MarkdownStreamFormatter()
    
    stream = stream_openai_api(
        system_prompt=system_prompt,
        user_content="\n".join(user_parts),
        base_url=args.server,
        api_key=args.key,
        model=args.model,
    )
    
    for text_chunk in stream:
        # 1. 经过格式化器拿到控制台带颜色的字符
        formatted_chunk = md_formatter.feed(text_chunk)
        # 2. 打印彩色输出
        print(formatted_chunk, end="", flush=True)
        # 3. 数组记录原始无 ANSI 污染的纯净文本用于存入文件
        full_ai_response.append(text_chunk)
        
    print("\033[0m\n\n" + "=" * 72) # \033[0m 防止任何颜色泄漏到下一个终端操作

    if args.output:
        out_path = Path(args.output)
        full_report = score_report + "\n\n" + "=" * 72 + "\n  AI 综合评估报告\n" + "=" * 72 + "\n\n" + "".join(full_ai_response)
        out_path.write_text(full_report, encoding="utf-8")
        print(f"[信息] 完整纯净版评估报告已保存至: {out_path.resolve()}")

if __name__ == "__main__":
    main()