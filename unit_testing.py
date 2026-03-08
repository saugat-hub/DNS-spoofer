"""
Unit Tests for DNS Spoofing Simulator
Run using: python test_dns.py
"""

import unittest
import datetime
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Optional
import random
import time
import hashlib


@dataclass
class DNSRecord:
    domain: str
    real_ip: str
    spoofed_ip: str
    ttl: int = 300
    record_type: str = "A"
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().strftime("%H:%M:%S"))


@dataclass
class DNSQuery:
    query_id: str
    domain: str
    client_ip: str
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().strftime("%H:%M:%S"))
    resolved_ip: Optional[str] = None
    spoofed: bool = False
    status: str = "PENDING"


class DNSCache:
    def __init__(self, capacity: int = 10):
        self.capacity = capacity
        self._cache = OrderedDict()

    def get(self, domain):
        if domain not in self._cache:
            return None
        self._cache.move_to_end(domain)
        return self._cache[domain]

    def put(self, record):
        domain = record.domain
        if domain in self._cache:
            self._cache.move_to_end(domain)
        self._cache[domain] = record
        if len(self._cache) > self.capacity:
            self._cache.popitem(last=False)

    def remove(self, domain):
        if domain in self._cache:
            del self._cache[domain]
            return True
        return False

    def clear(self):
        self._cache.clear()

    def __len__(self):
        return len(self._cache)


class LegitimateResolver:
    _database = {
        "google.com":        "142.250.80.46",
        "facebook.com":      "157.240.241.35",
        "amazon.com":        "205.251.242.103",
        "bankofamerica.com": "171.161.224.9",
        "paypal.com":        "66.211.169.3",
        "twitter.com":       "104.244.42.65",
        "github.com":        "140.82.114.4",
        "netflix.com":       "54.74.66.71",
        "apple.com":         "17.253.144.10",
        "microsoft.com":     "20.231.239.246",
    }

    @classmethod
    def resolve(cls, domain):
        return cls._database.get(domain.lower())

    @classmethod
    def all_domains(cls):
        return list(cls._database.keys())


class SpoofingEngine:
    def __init__(self):
        self.spoofed_table = {}
        self.query_log = deque(maxlen=200)
        self.cache = DNSCache(capacity=15)
        self._query_counter = 0
        self.active = False
        self.intercept_rate = 100

    def add_spoof_entry(self, domain, attacker_ip):
        self.spoofed_table[domain.lower()] = attacker_ip

    def remove_spoof_entry(self, domain):
        self.spoofed_table.pop(domain.lower(), None)

    def _generate_query_id(self):
        self._query_counter += 1
        raw = f"{self._query_counter}{time.time()}"
        return hashlib.md5(raw.encode()).hexdigest()[:8].upper()

    def resolve(self, domain, client_ip):
        qid = self._generate_query_id()
        query = DNSQuery(query_id=qid, domain=domain, client_ip=client_ip)
        cached = self.cache.get(domain)
        if cached:
            query.resolved_ip = cached.spoofed_ip
            query.status = "CACHE HIT"
            self.query_log.appendleft(query)
            return query
        real_ip = LegitimateResolver.resolve(domain) or "NXDOMAIN"
        resolved_ip = real_ip
        spoofed = False
        attacker_ip = self.spoofed_table.get(domain.lower())
        if self.active and attacker_ip and real_ip != "NXDOMAIN":
            roll = random.randint(1, 100)
            if roll <= self.intercept_rate:
                resolved_ip = attacker_ip
                spoofed = True
        query.resolved_ip = resolved_ip
        query.spoofed = spoofed
        query.status = "SPOOFED" if spoofed else "LEGITIMATE"
        self.cache.put(DNSRecord(domain=domain, real_ip=real_ip, spoofed_ip=resolved_ip))
        self.query_log.appendleft(query)
        return query

    def statistics(self):
        total = len(self.query_log)
        spoofed = sum(1 for q in self.query_log if q.spoofed)
        return {"total": total, "spoofed": spoofed}


# ── TEST CLASS 1: DNS CACHE ──────────────────

class TestDNSCache(unittest.TestCase):

    def setUp(self):
        self.cache = DNSCache(capacity=3)

    def test_1_put_and_get(self):
        self.cache.put(DNSRecord("example.com", "1.1.1.1", "9.9.9.9"))
        result = self.cache.get("example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result.domain, "example.com")

    def test_2_capacity_eviction(self):
        for i in range(4):
            self.cache.put(DNSRecord(f"site{i}.com", f"1.1.1.{i}", f"2.2.2.{i}"))
        self.assertIsNone(self.cache.get("site0.com"))

    def test_3_remove(self):
        self.cache.put(DNSRecord("test.com", "1.1.1.1", "2.2.2.2"))
        self.assertTrue(self.cache.remove("test.com"))
        self.assertIsNone(self.cache.get("test.com"))

    def test_4_clear(self):
        self.cache.put(DNSRecord("a.com", "1.1.1.1", "2.2.2.2"))
        self.cache.clear()
        self.assertEqual(len(self.cache), 0)


# ── TEST CLASS 2: SPOOFING ENGINE ────────────

class TestSpoofingEngine(unittest.TestCase):

    def setUp(self):
        self.engine = SpoofingEngine()

    def test_1_legitimate_resolution(self):
        query = self.engine.resolve("google.com", "192.168.1.1")
        self.assertFalse(query.spoofed)
        self.assertEqual(query.status, "LEGITIMATE")

    def test_2_spoofing_active(self):
        self.engine.active = True
        self.engine.intercept_rate = 100
        self.engine.add_spoof_entry("google.com", "6.6.6.6")
        query = self.engine.resolve("google.com", "192.168.1.5")
        self.assertTrue(query.spoofed)
        self.assertEqual(query.resolved_ip, "6.6.6.6")

    def test_3_remove_spoof_entry(self):
        self.engine.add_spoof_entry("evil.com", "5.5.5.5")
        self.engine.remove_spoof_entry("evil.com")
        self.assertNotIn("evil.com", self.engine.spoofed_table)

    def test_4_statistics(self):
        self.engine.active = True
        self.engine.intercept_rate = 100
        self.engine.add_spoof_entry("google.com", "6.6.6.6")
        self.engine.resolve("google.com", "10.0.0.1")
        stats = self.engine.statistics()
        self.assertGreaterEqual(stats["total"], 1)

    def test_5_nxdomain(self):
        query = self.engine.resolve("notarealsite12345.xyz", "10.0.0.1")
        self.assertEqual(query.resolved_ip, "NXDOMAIN")


# ── TEST CLASS 3: LEGITIMATE RESOLVER ────────

class TestLegitimateResolver(unittest.TestCase):

    def test_1_known_domain(self):
        ip = LegitimateResolver.resolve("google.com")
        self.assertEqual(ip, "142.250.80.46")

    def test_2_unknown_domain(self):
        ip = LegitimateResolver.resolve("doesnotexist.test")
        self.assertIsNone(ip)

    def test_3_all_domains(self):
        domains = LegitimateResolver.all_domains()
        self.assertGreater(len(domains), 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)