# analyzer.py (improved)
import hashlib
import ipaddress
from scapy.all import rdpcap, DNS, Raw, TCP, IP, IPv6
from collections import defaultdict
from typing import Dict, Any, Tuple, Optional
import logging
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# Thresholds from environment with defaults
LARGE_FLOW_BYTES = int(os.getenv("LARGE_FLOW_BYTES", "50000"))
LARGE_POST_BYTES = int(os.getenv("LARGE_POST_BYTES", "20000"))
DNS_QUERY_BURST = int(os.getenv("DNS_QUERY_BURST", "5"))
BURSTY_PKT = int(os.getenv("BURSTY_PKT", "10"))
DNS_TXT_SIZE_THRESHOLD = int(os.getenv("DNS_TXT_SIZE_THRESHOLD", "100"))
ENTROPY_THRESHOLD = float(os.getenv("ENTROPY_THRESHOLD", "7.5"))  # High entropy indicates encryption/encoding

log = logging.getLogger(__name__)


def _flow_id(five_tuple: Tuple) -> str:
    """
    Generate deterministic short id for a 5-tuple.
    Normalizes bidirectional flows to same ID.
    """
    src, dst, sport, dport, proto = five_tuple
    # Normalize: lower tuple first
    if (src, sport) > (dst, dport):
        src, dst, sport, dport = dst, src, dport, sport
    
    key = f"{src}:{sport}|{dst}:{dport}|{proto}"
    m = hashlib.sha1(key.encode())
    return m.hexdigest()[:12]


def _is_private(ip_str: str) -> bool:
    """Return True if ip_str is in private/reserved ranges (IPv4/IPv6)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (ip.is_private or ip.is_loopback or 
                ip.is_reserved or ip.is_link_local)
    except Exception:
        return False


def _calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    High entropy (>7.5) suggests encryption or encoding.
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    
    # Calculate entropy
    import math
    entropy = 0.0
    data_len = len(data)
    
    for count in freq.values():
        if count > 0:
            p = count / data_len
            entropy -= p * math.log2(p)
    
    return entropy


def _extract_payload(packet) -> Optional[bytes]:
    """Extract raw payload from packet if available."""
    try:
        if Raw in packet:
            return bytes(packet[Raw].load)
    except Exception:
        pass
    return None


def _is_http_post(payload: bytes) -> bool:
    """Check if payload looks like HTTP POST request."""
    if not payload:
        return False
    try:
        # Check first 100 bytes for POST
        header = payload[:100].decode('utf-8', errors='ignore').upper()
        return header.startswith('POST ')
    except Exception:
        return False


class FlowAccumulator:
    """Helper class to accumulate flow statistics."""
    
    def __init__(self):
        self.bytes = 0
        self.pkts = 0
        self.start = None
        self.end = None
        self.protocol = None
        self.timeline = defaultdict(lambda: {"pkts": 0, "bytes": 0})
        self.payloads = []  # Sample payloads for analysis
        self.flags = set()  # TCP flags seen
        self.has_post = False
    
    def add_packet(self, timestamp: float, payload_len: int, 
                   protocol: str, payload: Optional[bytes] = None,
                   tcp_flags: Optional[str] = None):
        """Add packet to flow accumulator."""
        self.pkts += 1
        self.bytes += payload_len
        self.protocol = protocol
        
        if self.start is None:
            self.start = timestamp
        self.end = timestamp
        
        # Timeline bucket
        bucket = int(timestamp)
        self.timeline[bucket]["pkts"] += 1
        self.timeline[bucket]["bytes"] += payload_len
        
        # Sample payloads (keep first 5 for analysis)
        if payload and len(self.payloads) < 5:
            self.payloads.append(payload)
        
        # Track TCP flags
        if tcp_flags:
            self.flags.add(tcp_flags)
        
        # Check for HTTP POST
        if payload and not self.has_post:
            self.has_post = _is_http_post(payload)
    
    def get_timeline_list(self):
        """Convert timeline dict to sorted list."""
        return [
            {"ts": ts, "pkts": bucket["pkts"], "bytes": bucket["bytes"]}
            for ts, bucket in sorted(self.timeline.items())
        ]
    
    def analyze_payloads(self) -> Dict[str, Any]:
        """Analyze accumulated payloads for suspicious patterns."""
        if not self.payloads:
            return {}
        
        # Calculate average entropy
        entropies = [_calculate_entropy(p) for p in self.payloads if p]
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        
        return {
            "avg_entropy": round(avg_entropy, 2),
            "high_entropy": avg_entropy > ENTROPY_THRESHOLD,
            "sample_count": len(self.payloads)
        }


def analyze_pcap(pcap_file_path: str) -> Dict[str, Any]:
    """
    Analyze a PCAP file and return comprehensive network flow analysis.
    
    Returns:
        {
            "flows": {flow_id: {metadata, timeline, analysis}},
            "suspicious": [{type, details, reasons}],
            "summary": {statistics},
            "metadata": {pcap_info}
        }
    """
    log.info(f"Starting analysis of {pcap_file_path}")
    
    flows = {}
    acc = defaultdict(FlowAccumulator)
    
    # DNS tracking
    dns_query_counter = defaultdict(int)
    dns_txt_sizes = defaultdict(list)
    
    # Traffic pattern tracking
    time_counter = defaultdict(int)
    unique_ips = set()
    protocols = defaultdict(int)
    
    # Read PCAP
    try:
        pkts = rdpcap(pcap_file_path)
        log.info(f"Read {len(pkts)} packets from {pcap_file_path}")
    except Exception as e:
        log.error(f"Failed to read PCAP: {e}")
        raise RuntimeError(f"Failed to read PCAP: {e}")
    
    if not pkts:
        log.warning("Empty PCAP file")
        return {
            "flows": {},
            "suspicious": [],
            "suspicious_count": 0,
            "flow_count": 0,
            "total_bytes": 0,
            "summary": {"flow_count": 0, "suspicious_count": 0, "total_bytes": 0}
        }
    
    # Process packets
    for idx, p in enumerate(pkts):
        try:
            # Get timestamp
            timestamp = float(p.time) if hasattr(p, 'time') else 0.0
            
            # Extract IP layer (IPv4 or IPv6)
            ip_layer = None
            if IP in p:
                ip_layer = p[IP]
            elif IPv6 in p:
                ip_layer = p[IPv6]
            
            if not ip_layer:
                continue
            
            src = ip_layer.src
            dst = ip_layer.dst
            unique_ips.add(src)
            unique_ips.add(dst)
            
            # Get transport layer
            nxt = ip_layer.payload
            proto = type(nxt).__name__
            protocols[proto] += 1
            
            sport = getattr(nxt, 'sport', 0)
            dport = getattr(nxt, 'dport', 0)
            
            # Extract payload
            payload = _extract_payload(p)
            payload_len = len(bytes(p))
            
            # Get TCP flags if TCP
            tcp_flags = None
            if TCP in p:
                tcp_layer = p[TCP]
                flags = []
                if tcp_layer.flags.S: flags.append('SYN')
                if tcp_layer.flags.A: flags.append('ACK')
                if tcp_layer.flags.F: flags.append('FIN')
                if tcp_layer.flags.R: flags.append('RST')
                if tcp_layer.flags.P: flags.append('PSH')
                tcp_flags = '|'.join(flags) if flags else None
            
            # Build five-tuple
            five_tuple = (src, dst, sport, dport, proto)
            
            # Accumulate flow data
            flow_acc = acc[five_tuple]
            flow_acc.add_packet(timestamp, payload_len, proto, payload, tcp_flags)
            
            # Track per-source traffic rate
            bucket = int(timestamp)
            time_counter[(src, bucket)] += 1
            
            # DNS analysis
            if DNS in p:
                dns = p[DNS]
                qr = int(getattr(dns, 'qr', 0))
                
                # Extract query name
                qname = None
                if hasattr(dns, 'qd') and dns.qd:
                    try:
                        qname = dns.qd.qname.decode('utf-8', 'ignore').rstrip('.').lower()
                    except Exception:
                        qname = str(dns.qd.qname).rstrip('.').lower()
                
                # Count queries
                if qr == 0 and qname:
                    dns_query_counter[qname] += 1
                
                # Analyze TXT responses
                if qr == 1 and hasattr(dns, 'an') and dns.an:
                    try:
                        i = 0
                        while True:
                            rr = dns.an[i]
                            if getattr(rr, 'type', None) == 16:  # TXT record
                                rdata = getattr(rr, 'rdata', b'')
                                if isinstance(rdata, list):
                                    txt_bytes = b''.join([
                                        t if isinstance(t, bytes) else str(t).encode()
                                        for t in rdata
                                    ])
                                elif isinstance(rdata, str):
                                    txt_bytes = rdata.encode('utf-8', 'ignore')
                                elif isinstance(rdata, bytes):
                                    txt_bytes = rdata
                                else:
                                    txt_bytes = str(rdata).encode('utf-8', 'ignore')
                                
                                if qname:
                                    dns_txt_sizes[qname].append(len(txt_bytes))
                            i += 1
                    except (IndexError, AttributeError):
                        pass
        
        except Exception as e:
            log.debug(f"Error processing packet {idx}: {e}")
            continue
    
    log.info(f"Processed {len(pkts)} packets, found {len(acc)} flows")
    
    # Convert accumulated flows to final structure
    for five_tuple, flow_acc in acc.items():
        fid = _flow_id(five_tuple)
        
        # Analyze payloads
        payload_analysis = flow_acc.analyze_payloads()
        
        flows[fid] = {
            "id": fid,
            "five_tuple": {
                "src": five_tuple[0],
                "dst": five_tuple[1],
                "sport": five_tuple[2],
                "dport": five_tuple[3],
                "protocol": five_tuple[4],
            },
            "bytes": flow_acc.bytes,
            "packets": flow_acc.pkts,
            "start": flow_acc.start,
            "end": flow_acc.end,
            "duration": round(flow_acc.end - flow_acc.start, 3) if flow_acc.start else None,
            "timeline": flow_acc.get_timeline_list(),
            "tcp_flags": list(flow_acc.flags) if flow_acc.flags else None,
            "has_http_post": flow_acc.has_post,
            "payload_analysis": payload_analysis
        }
    
    # Detect suspicious activity
    suspicious = []
    
    # Flow-based heuristics
    for fid, f in flows.items():
        ft = f["five_tuple"]
        src = ft["src"]
        dst = ft["dst"]
        
        reasons = []
        
        # Determine flow direction
        src_private = _is_private(src)
        dst_private = _is_private(dst)
        looks_outbound = src_private and not dst_private
        
        # Large outbound transfer
        if f["bytes"] > LARGE_FLOW_BYTES:
            if looks_outbound:
                reasons.append(f"Large outbound flow: {f['bytes']:,} bytes")
            else:
                reasons.append(f"Large flow: {f['bytes']:,} bytes")
        
        # HTTP POST detection with size check
        if f.get("has_http_post") and f["bytes"] > LARGE_POST_BYTES:
            reasons.append(f"Large HTTP POST: {f['bytes']:,} bytes")
        
        # High entropy (encrypted/encoded data)
        payload_analysis = f.get("payload_analysis", {})
        if payload_analysis.get("high_entropy"):
            entropy = payload_analysis.get("avg_entropy", 0)
            reasons.append(f"High entropy data detected (avg: {entropy:.2f})")
        
        # Suspicious ports (common backdoor/C2 ports)
        suspicious_ports = {4444, 5555, 6666, 7777, 8080, 8888, 9999, 31337}
        if ft["dport"] in suspicious_ports or ft["sport"] in suspicious_ports:
            port = ft["dport"] if ft["dport"] in suspicious_ports else ft["sport"]
            reasons.append(f"Suspicious port usage: {port}")
        
        # Long-duration connections
        if f.get("duration") and f["duration"] > 300:  # 5 minutes
            duration_min = f["duration"] / 60
            reasons.append(f"Long-duration connection: {duration_min:.1f} minutes")
        
        if reasons:
            suspicious.append({
                "type": "flow",
                "id": fid,
                "src": src,
                "dst": dst,
                "sport": ft["sport"],
                "dport": ft["dport"],
                "protocol": ft["protocol"],
                "reasons": reasons,
                "bytes": f["bytes"],
                "packets": f["packets"],
                "severity": "high" if len(reasons) > 2 else "medium"
            })
    
    # DNS anomalies
    for dom, cnt in dns_query_counter.items():
        if cnt > DNS_QUERY_BURST:
            suspicious.append({
                "type": "dns",
                "domain": dom,
                "count": cnt,
                "reasons": [f"Excessive DNS queries: {cnt} requests"],
                "severity": "medium"
            })
    
    # Large TXT responses (data exfiltration via DNS)
    for dom, sizes in dns_txt_sizes.items():
        max_txt = max(sizes) if sizes else 0
        if max_txt > DNS_TXT_SIZE_THRESHOLD or len(sizes) > 3:
            suspicious.append({
                "type": "dns_txt",
                "domain": dom,
                "max_txt_bytes": max_txt,
                "count": len(sizes),
                "reasons": [
                    f"Suspicious DNS TXT responses: max {max_txt} bytes, "
                    f"{len(sizes)} responses"
                ],
                "severity": "high"
            })
    
    # Bursty traffic
    for (src, bucket), cnt in time_counter.items():
        if cnt > BURSTY_PKT:
            suspicious.append({
                "type": "burst",
                "src": src,
                "timestamp": bucket,
                "count": cnt,
                "reasons": [f"Traffic burst: {cnt} packets/second"],
                "severity": "low"
            })
    
    # Calculate summary statistics
    total_bytes = sum(f["bytes"] for f in flows.values())
    total_packets = sum(f["packets"] for f in flows.values())
    
    # Get time range
    all_times = [f["start"] for f in flows.values() if f["start"]]
    time_range = {
        "start": min(all_times) if all_times else None,
        "end": max(all_times) if all_times else None
    }
    
    summary = {
        "flow_count": len(flows),
        "suspicious_count": len(suspicious),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "unique_ips": len(unique_ips),
        "protocols": dict(protocols),
        "time_range": time_range,
        "severity_breakdown": {
            "high": len([s for s in suspicious if s.get("severity") == "high"]),
            "medium": len([s for s in suspicious if s.get("severity") == "medium"]),
            "low": len([s for s in suspicious if s.get("severity") == "low"])
        }
    }
    
    log.info(f"Analysis complete: {len(flows)} flows, {len(suspicious)} suspicious items")
    
    return {
        "flows": flows,
        "suspicious": suspicious,
        "suspicious_count": len(suspicious),
        "flow_count": len(flows),
        "total_bytes": total_bytes,
        "summary": summary
    }