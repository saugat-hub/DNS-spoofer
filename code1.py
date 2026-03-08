"""
DNS Spoofing Simulator
======================
Educational tool for Ethical Hacking & Cyber Security coursework.
Simulates DNS spoofing attacks using OOP, data structures, and algorithms.
Includes Tkinter GUI, unit testing, and logging.

Author: Student Project
Module: Ethical Hacking and Cyber Security
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import random
import hashlib
import json
import datetime
import unittest
import io
import sys
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────
#  DATA STRUCTURES & MODELS
# ─────────────────────────────────────────────

@dataclass
class DNSRecord:
    """Represents a single DNS record entry."""
    domain: str
    real_ip: str
    spoofed_ip: str
    ttl: int = 300
    record_type: str = "A"
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().strftime("%H:%M:%S"))

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "real_ip": self.real_ip,
            "spoofed_ip": self.spoofed_ip,
            "ttl": self.ttl,
            "record_type": self.record_type,
            "timestamp": self.timestamp,
        }


@dataclass
class DNSQuery:
    """Represents a DNS query made by a client."""
    query_id: str
    domain: str
    client_ip: str
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().strftime("%H:%M:%S"))
    resolved_ip: Optional[str] = None
    spoofed: bool = False
    status: str = "PENDING"

    def to_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "domain": self.domain,
            "client_ip": self.client_ip,
            "timestamp": self.timestamp,
            "resolved_ip": self.resolved_ip,
            "spoofed": self.spoofed,
            "status": self.status,
        }


# ─────────────────────────────────────────────
#  DNS CACHE (LRU-style with OrderedDict)
# ─────────────────────────────────────────────

class DNSCache:
    """
    LRU Cache for DNS records.
    Uses OrderedDict to maintain insertion/access order.
    """

    def __init__(self, capacity: int = 10):
        self.capacity = capacity
        self._cache: OrderedDict[str, DNSRecord] = OrderedDict()

    def get(self, domain: str) -> Optional[DNSRecord]:
        if domain not in self._cache:
            return None
        self._cache.move_to_end(domain)
        return self._cache[domain]

    def put(self, record: DNSRecord):
        domain = record.domain
        if domain in self._cache:
            self._cache.move_to_end(domain)
        self._cache[domain] = record
        if len(self._cache) > self.capacity:
            self._cache.popitem(last=False)

    def remove(self, domain: str) -> bool:
        if domain in self._cache:
            del self._cache[domain]
            return True
        return False

    def all_records(self) -> list:
        return list(self._cache.values())

    def clear(self):
        self._cache.clear()

    def __len__(self):
        return len(self._cache)


# ─────────────────────────────────────────────
#  LEGITIMATE DNS SERVER (simulated)
# ─────────────────────────────────────────────

class LegitimateResolver:
    """Simulates a real DNS resolver with a fixed database."""

    _database = {
        "google.com":      "142.250.80.46",
        "facebook.com":    "157.240.241.35",
        "amazon.com":      "205.251.242.103",
        "bankofamerica.com": "171.161.224.9",
        "paypal.com":      "66.211.169.3",
        "twitter.com":     "104.244.42.65",
        "github.com":      "140.82.114.4",
        "netflix.com":     "54.74.66.71",
        "apple.com":       "17.253.144.10",
        "microsoft.com":   "20.231.239.246",
    }

    @classmethod
    def resolve(cls, domain: str) -> Optional[str]:
        """Return real IP for domain, or None if unknown."""
        time.sleep(random.uniform(0.05, 0.15))  # simulate network latency
        return cls._database.get(domain.lower())

    @classmethod
    def all_domains(cls) -> list:
        return list(cls._database.keys())


# ─────────────────────────────────────────────
#  ATTACKER / SPOOFING ENGINE
# ─────────────────────────────────────────────

class SpoofingEngine:
    """
    Core DNS spoofing logic.
    Maintains a spoofed record table and intercepts queries.
    """

    def __init__(self):
        self.spoofed_table: dict[str, str] = {}   # domain -> attacker_ip
        self.query_log: deque[DNSQuery] = deque(maxlen=200)
        self.cache = DNSCache(capacity=15)
        self._query_counter = 0
        self.active = False
        self.intercept_rate = 100   # percentage (0–100)

    def add_spoof_entry(self, domain: str, attacker_ip: str):
        self.spoofed_table[domain.lower()] = attacker_ip

    def remove_spoof_entry(self, domain: str):
        self.spoofed_table.pop(domain.lower(), None)

    def clear_spoof_table(self):
        self.spoofed_table.clear()

    def _generate_query_id(self) -> str:
        self._query_counter += 1
        raw = f"{self._query_counter}{time.time()}"
        return hashlib.md5(raw.encode()).hexdigest()[:8].upper()

    def resolve(self, domain: str, client_ip: str) -> DNSQuery:
        """
        Process a DNS query.
        If spoofing is active and domain is in spoofed table,
        return attacker-controlled IP (with probability = intercept_rate).
        """
        qid = self._generate_query_id()
        query = DNSQuery(query_id=qid, domain=domain, client_ip=client_ip)

        # Check cache first
        cached = self.cache.get(domain)
        if cached:
            query.resolved_ip = cached.spoofed_ip if cached.spoofed_ip != cached.real_ip else cached.real_ip
            query.spoofed = cached.spoofed_ip != cached.real_ip
            query.status = "CACHE HIT"
            self.query_log.appendleft(query)
            return query

        # Legitimate resolution
        real_ip = LegitimateResolver.resolve(domain) or "NXDOMAIN"

        # Spoofing decision
        spoofed = False
        resolved_ip = real_ip
        attacker_ip = self.spoofed_table.get(domain.lower())

        if self.active and attacker_ip and real_ip != "NXDOMAIN":
            roll = random.randint(1, 100)
            if roll <= self.intercept_rate:
                resolved_ip = attacker_ip
                spoofed = True

        query.resolved_ip = resolved_ip
        query.spoofed = spoofed
        query.status = "SPOOFED" if spoofed else "LEGITIMATE"

        # Cache the result
        record = DNSRecord(
            domain=domain,
            real_ip=real_ip if real_ip != "NXDOMAIN" else "",
            spoofed_ip=resolved_ip,
        )
        record.spoofed_ip = resolved_ip  # store what was actually returned
        self.cache.put(record)
        self.query_log.appendleft(query)
        return query

    def statistics(self) -> dict:
        total = len(self.query_log)
        spoofed = sum(1 for q in self.query_log if q.spoofed)
        legit = total - spoofed
        return {
            "total": total,
            "spoofed": spoofed,
            "legitimate": legit,
            "spoof_rate": f"{(spoofed/total*100):.1f}%" if total else "0%",
        }


# ─────────────────────────────────────────────
#  UNIT TESTS
# ─────────────────────────────────────────────

class TestDNSCache(unittest.TestCase):
    def setUp(self):
        self.cache = DNSCache(capacity=3)

    def test_put_and_get(self):
        r = DNSRecord("example.com", "1.1.1.1", "9.9.9.9")
        self.cache.put(r)
        result = self.cache.get("example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result.domain, "example.com")

    def test_capacity_eviction(self):
        for i in range(4):
            self.cache.put(DNSRecord(f"site{i}.com", f"1.1.1.{i}", f"2.2.2.{i}"))
        self.assertIsNone(self.cache.get("site0.com"))

    def test_remove(self):
        self.cache.put(DNSRecord("test.com", "1.1.1.1", "2.2.2.2"))
        removed = self.cache.remove("test.com")
        self.assertTrue(removed)
        self.assertIsNone(self.cache.get("test.com"))

    def test_clear(self):
        self.cache.put(DNSRecord("a.com", "1.1.1.1", "2.2.2.2"))
        self.cache.clear()
        self.assertEqual(len(self.cache), 0)


class TestSpoofingEngine(unittest.TestCase):
    def setUp(self):
        self.engine = SpoofingEngine()

    def test_legitimate_resolution(self):
        query = self.engine.resolve("google.com", "192.168.1.1")
        self.assertEqual(query.domain, "google.com")
        self.assertFalse(query.spoofed)

    def test_spoofing_active(self):
        self.engine.active = True
        self.engine.intercept_rate = 100
        self.engine.add_spoof_entry("google.com", "6.6.6.6")
        query = self.engine.resolve("google.com", "192.168.1.5")
        self.assertTrue(query.spoofed)
        self.assertEqual(query.resolved_ip, "6.6.6.6")

    def test_remove_spoof_entry(self):
        self.engine.add_spoof_entry("evil.com", "5.5.5.5")
        self.engine.remove_spoof_entry("evil.com")
        self.assertNotIn("evil.com", self.engine.spoofed_table)

    def test_statistics(self):
        self.engine.active = True
        self.engine.intercept_rate = 100
        self.engine.add_spoof_entry("google.com", "6.6.6.6")
        self.engine.resolve("google.com", "10.0.0.1")
        stats = self.engine.statistics()
        self.assertGreaterEqual(stats["total"], 1)

    def test_nxdomain(self):
        query = self.engine.resolve("notarealsite12345.xyz", "10.0.0.1")
        self.assertEqual(query.resolved_ip, "NXDOMAIN")


class TestLegitimateResolver(unittest.TestCase):
    def test_known_domain(self):
        ip = LegitimateResolver.resolve("google.com")
        self.assertIsNotNone(ip)

    def test_unknown_domain(self):
        ip = LegitimateResolver.resolve("doesnotexist.test")
        self.assertIsNone(ip)


# ─────────────────────────────────────────────
#  TKINTER GUI
# ─────────────────────────────────────────────

class DNSSpoofingSimulatorApp(tk.Tk):
    """Main application window."""

    DARK_BG      = "#0d1117"
    PANEL_BG     = "#161b22"
    BORDER       = "#30363d"
    GREEN        = "#3fb950"
    RED          = "#f85149"
    YELLOW       = "#d29922"
    BLUE         = "#58a6ff"
    TEXT         = "#e6edf3"
    MUTED        = "#8b949e"
    FONT_MONO    = ("Courier New", 10)
    FONT_UI      = ("Segoe UI", 10)
    FONT_TITLE   = ("Segoe UI", 12, "bold")

    def __init__(self):
        super().__init__()
        self.engine = SpoofingEngine()
        self.simulation_running = False
        self._sim_thread = None

        self.title("🛡 DNS Spoofing Simulator — Ethical Hacking Coursework")
        self.geometry("1100x720")
        self.resizable(True, True)
        self.configure(bg=self.DARK_BG)

        self._apply_style()
        self._build_ui()

    # ── Style ──────────────────────────────────

    def _apply_style(self):
        style = ttk.Style(self)
        style.theme_use("default")

        style.configure("TNotebook",        background=self.DARK_BG,  borderwidth=0)
        style.configure("TNotebook.Tab",    background=self.PANEL_BG, foreground=self.MUTED,
                        padding=[14, 6],    font=self.FONT_UI)
        style.map("TNotebook.Tab",
                  background=[("selected", self.DARK_BG)],
                  foreground=[("selected", self.BLUE)])

        style.configure("Treeview",         background=self.PANEL_BG, foreground=self.TEXT,
                        fieldbackground=self.PANEL_BG, rowheight=24,
                        font=self.FONT_MONO, borderwidth=0)
        style.configure("Treeview.Heading", background=self.BORDER,   foreground=self.MUTED,
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview",               background=[("selected", "#1f2937")])

        style.configure("TLabelframe",      background=self.PANEL_BG, foreground=self.MUTED,
                        bordercolor=self.BORDER)
        style.configure("TLabelframe.Label",background=self.PANEL_BG, foreground=self.BLUE,
                        font=self.FONT_TITLE)

    # ── Layout ─────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=self.PANEL_BG, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⚡ DNS Spoofing Simulator",
                 font=("Segoe UI", 16, "bold"), bg=self.PANEL_BG,
                 fg=self.RED).pack(side="left", padx=20)
        tk.Label(hdr, text="Educational Tool — Ethical Hacking & Cyber Security",
                 font=self.FONT_UI, bg=self.PANEL_BG, fg=self.MUTED).pack(side="left")

        # Status bar
        self.status_var = tk.StringVar(value="● Spoofing: INACTIVE")
        tk.Label(hdr, textvariable=self.status_var, font=self.FONT_UI,
                 bg=self.PANEL_BG, fg=self.MUTED).pack(side="right", padx=20)

        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self._tab_attack(nb)
        self._tab_query(nb)
        self._tab_log(nb)
        self._tab_cache(nb)
        self._tab_tests(nb)
        self._tab_about(nb)

    # ── Tab 1: Attack Control ───────────────────

    def _tab_attack(self, nb):
        frame = tk.Frame(nb, bg=self.DARK_BG)
        nb.add(frame, text=" ⚔  Attack Control ")

        left = tk.Frame(frame, bg=self.DARK_BG)
        left.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        right = tk.Frame(frame, bg=self.DARK_BG)
        right.pack(side="right", fill="y", padx=10, pady=10)

        # ── Spoof Table entry ──
        entry_frame = tk.LabelFrame(left, text=" Add Spoof Entry ",
                                    bg=self.PANEL_BG, fg=self.BLUE,
                                    font=self.FONT_TITLE, bd=1, relief="solid",
                                    highlightbackground=self.BORDER)
        entry_frame.pack(fill="x", pady=(0, 10))

        row1 = tk.Frame(entry_frame, bg=self.PANEL_BG)
        row1.pack(fill="x", padx=10, pady=5)
        tk.Label(row1, text="Domain:", width=12, anchor="w",
                 bg=self.PANEL_BG, fg=self.MUTED, font=self.FONT_UI).pack(side="left")
        self.spoof_domain_var = tk.StringVar()
        domain_combo = ttk.Combobox(row1, textvariable=self.spoof_domain_var, width=28,
                                    values=LegitimateResolver.all_domains(), font=self.FONT_MONO)
        domain_combo.pack(side="left", padx=5)

        row2 = tk.Frame(entry_frame, bg=self.PANEL_BG)
        row2.pack(fill="x", padx=10, pady=5)
        tk.Label(row2, text="Attacker IP:", width=12, anchor="w",
                 bg=self.PANEL_BG, fg=self.MUTED, font=self.FONT_UI).pack(side="left")
        self.attacker_ip_var = tk.StringVar(value="192.168.1.99")
        tk.Entry(row2, textvariable=self.attacker_ip_var, width=30,
                 bg=self.DARK_BG, fg=self.GREEN, insertbackground=self.GREEN,
                 font=self.FONT_MONO, bd=1, relief="solid").pack(side="left", padx=5)

        btn_row = tk.Frame(entry_frame, bg=self.PANEL_BG)
        btn_row.pack(fill="x", padx=10, pady=(0, 10))
        self._btn(btn_row, "➕ Add Entry", self._add_spoof_entry, self.GREEN).pack(side="left", padx=4)
        self._btn(btn_row, "🗑 Remove Selected", self._remove_spoof_entry, self.YELLOW).pack(side="left", padx=4)
        self._btn(btn_row, "💣 Clear All", self._clear_spoof_table, self.RED).pack(side="left", padx=4)

        # ── Spoof table ──
        tbl_frame = tk.LabelFrame(left, text=" Spoof Table (Attack Map) ",
                                   bg=self.PANEL_BG, fg=self.BLUE, font=self.FONT_TITLE,
                                   bd=1, relief="solid")
        tbl_frame.pack(fill="both", expand=True)

        cols = ("Domain", "Attacker IP")
        self.spoof_tree = ttk.Treeview(tbl_frame, columns=cols, show="headings", height=10)
        for c in cols:
            self.spoof_tree.heading(c, text=c)
            self.spoof_tree.column(c, width=200)
        self.spoof_tree.pack(fill="both", expand=True, padx=5, pady=5)
        self.spoof_tree.tag_configure("spoof", foreground=self.RED)

        # ── Right: Engine Controls ──
        ctrl = tk.LabelFrame(right, text=" Engine Control ",
                              bg=self.PANEL_BG, fg=self.BLUE, font=self.FONT_TITLE,
                              bd=1, relief="solid", width=260)
        ctrl.pack(fill="x", pady=(0, 10))

        self.attack_active_var = tk.BooleanVar(value=False)
        tk.Checkbutton(ctrl, text="  Enable Spoofing",
                       variable=self.attack_active_var, command=self._toggle_spoofing,
                       bg=self.PANEL_BG, fg=self.TEXT, selectcolor=self.DARK_BG,
                       activebackground=self.PANEL_BG, font=self.FONT_UI,
                       indicatoron=True).pack(anchor="w", padx=10, pady=(10, 5))

        tk.Label(ctrl, text="Intercept Rate (%):", bg=self.PANEL_BG, fg=self.MUTED,
                 font=self.FONT_UI).pack(anchor="w", padx=10)
        self.rate_var = tk.IntVar(value=100)
        tk.Scale(ctrl, from_=0, to=100, orient="horizontal", variable=self.rate_var,
                 command=self._update_rate, bg=self.PANEL_BG, fg=self.TEXT,
                 troughcolor=self.DARK_BG, highlightbackground=self.PANEL_BG,
                 length=220).pack(padx=10, pady=(0, 10))

        # Simulation
        sim = tk.LabelFrame(right, text=" Auto Simulation ",
                             bg=self.PANEL_BG, fg=self.BLUE, font=self.FONT_TITLE,
                             bd=1, relief="solid", width=260)
        sim.pack(fill="x", pady=(0, 10))

        tk.Label(sim, text="Client IP (simulated):", bg=self.PANEL_BG, fg=self.MUTED,
                 font=self.FONT_UI).pack(anchor="w", padx=10, pady=(10, 0))
        self.sim_client_var = tk.StringVar(value="10.0.0.42")
        tk.Entry(sim, textvariable=self.sim_client_var, width=22,
                 bg=self.DARK_BG, fg=self.BLUE, insertbackground=self.BLUE,
                 font=self.FONT_MONO, bd=1, relief="solid").pack(padx=10, pady=4)

        self._btn(sim, "▶ Start Simulation", self._start_simulation, self.GREEN).pack(padx=10, pady=4, fill="x")
        self._btn(sim, "■ Stop Simulation",  self._stop_simulation,  self.RED).pack(padx=10, pady=(0, 10), fill="x")

        # Stats
        stats_frame = tk.LabelFrame(right, text=" Statistics ",
                                     bg=self.PANEL_BG, fg=self.BLUE, font=self.FONT_TITLE,
                                     bd=1, relief="solid", width=260)
        stats_frame.pack(fill="x")

        self.stats_text = tk.Text(stats_frame, height=7, width=30,
                                   bg=self.DARK_BG, fg=self.TEXT, font=self.FONT_MONO,
                                   bd=0, state="disabled")
        self.stats_text.pack(padx=10, pady=10)
        self._update_stats()

    # ── Tab 2: Manual Query ─────────────────────

    def _tab_query(self, nb):
        frame = tk.Frame(nb, bg=self.DARK_BG)
        nb.add(frame, text=" 🔍 Manual Query ")

        wrapper = tk.Frame(frame, bg=self.DARK_BG)
        wrapper.pack(expand=True, fill="both", padx=30, pady=20)

        qf = tk.LabelFrame(wrapper, text=" Send DNS Query ",
                            bg=self.PANEL_BG, fg=self.BLUE, font=self.FONT_TITLE,
                            bd=1, relief="solid")
        qf.pack(fill="x", pady=(0, 15))

        row = tk.Frame(qf, bg=self.PANEL_BG)
        row.pack(fill="x", padx=15, pady=10)

        tk.Label(row, text="Domain:", width=12, anchor="w",
                 bg=self.PANEL_BG, fg=self.MUTED, font=self.FONT_UI).grid(row=0, column=0, sticky="w")
        self.q_domain_var = tk.StringVar()
        ttk.Combobox(row, textvariable=self.q_domain_var, width=30,
                     values=LegitimateResolver.all_domains(), font=self.FONT_MONO).grid(row=0, column=1, padx=5)

        tk.Label(row, text="Client IP:", width=12, anchor="w",
                 bg=self.PANEL_BG, fg=self.MUTED, font=self.FONT_UI).grid(row=1, column=0, sticky="w", pady=5)
        self.q_client_var = tk.StringVar(value="192.168.0.10")
        tk.Entry(row, textvariable=self.q_client_var, width=32,
                 bg=self.DARK_BG, fg=self.BLUE, insertbackground=self.BLUE,
                 font=self.FONT_MONO, bd=1, relief="solid").grid(row=1, column=1, padx=5)

        self._btn(qf, "⚡ Resolve", self._manual_query, self.BLUE).pack(pady=10)

        # Result display
        rf = tk.LabelFrame(wrapper, text=" Query Result ",
                           bg=self.PANEL_BG, fg=self.BLUE, font=self.FONT_TITLE,
                           bd=1, relief="solid")
        rf.pack(fill="both", expand=True)
        self.result_text = tk.Text(rf, bg=self.DARK_BG, fg=self.TEXT, font=self.FONT_MONO,
                                    bd=0, state="disabled")
        self.result_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.result_text.tag_configure("spoof",  foreground=self.RED)
        self.result_text.tag_configure("legit",  foreground=self.GREEN)
        self.result_text.tag_configure("header", foreground=self.BLUE, font=("Courier New", 10, "bold"))

    # ── Tab 3: Query Log ────────────────────────

    def _tab_log(self, nb):
        frame = tk.Frame(nb, bg=self.DARK_BG)
        nb.add(frame, text=" 📋 Query Log ")

        top = tk.Frame(frame, bg=self.DARK_BG)
        top.pack(fill="x", padx=10, pady=5)
        self._btn(top, "🔄 Refresh", self._refresh_log, self.BLUE).pack(side="left", padx=4)
        self._btn(top, "🗑 Clear Log", self._clear_log, self.RED).pack(side="left", padx=4)

        cols = ("Time", "ID", "Domain", "Client IP", "Resolved IP", "Status")
        self.log_tree = ttk.Treeview(frame, columns=cols, show="headings")
        widths = [80, 90, 160, 130, 130, 100]
        for c, w in zip(cols, widths):
            self.log_tree.heading(c, text=c)
            self.log_tree.column(c, width=w)
        self.log_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log_tree.tag_configure("spoofed", foreground=self.RED)
        self.log_tree.tag_configure("legit",   foreground=self.GREEN)
        self.log_tree.tag_configure("cache",   foreground=self.YELLOW)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=vsb.set)

    # ── Tab 4: Cache Viewer ─────────────────────

    def _tab_cache(self, nb):
        frame = tk.Frame(nb, bg=self.DARK_BG)
        nb.add(frame, text=" 🗄  DNS Cache ")

        top = tk.Frame(frame, bg=self.DARK_BG)
        top.pack(fill="x", padx=10, pady=5)
        self._btn(top, "🔄 Refresh", self._refresh_cache, self.BLUE).pack(side="left", padx=4)
        self._btn(top, "💣 Flush Cache", self._flush_cache, self.RED).pack(side="left", padx=4)

        cols = ("Domain", "Real IP", "Returned IP", "Spoofed?", "Time")
        self.cache_tree = ttk.Treeview(frame, columns=cols, show="headings")
        widths = [180, 150, 150, 90, 90]
        for c, w in zip(cols, widths):
            self.cache_tree.heading(c, text=c)
            self.cache_tree.column(c, width=w)
        self.cache_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.cache_tree.tag_configure("spoofed", foreground=self.RED)
        self.cache_tree.tag_configure("clean",   foreground=self.GREEN)

    # ── Tab 5: Unit Tests ───────────────────────

    def _tab_tests(self, nb):
        frame = tk.Frame(nb, bg=self.DARK_BG)
        nb.add(frame, text=" 🧪 Unit Tests ")

        top = tk.Frame(frame, bg=self.DARK_BG)
        top.pack(fill="x", padx=10, pady=8)
        self._btn(top, "▶ Run All Tests", self._run_tests, self.GREEN).pack(side="left", padx=4)

        self.test_output = scrolledtext.ScrolledText(
            frame, bg=self.DARK_BG, fg=self.TEXT, font=self.FONT_MONO,
            bd=0, state="disabled")
        self.test_output.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.test_output.tag_configure("pass", foreground=self.GREEN)
        self.test_output.tag_configure("fail", foreground=self.RED)
        self.test_output.tag_configure("info", foreground=self.BLUE)

    # ── Tab 6: About ────────────────────────────

    def _tab_about(self, nb):
        frame = tk.Frame(nb, bg=self.DARK_BG)
        nb.add(frame, text=" ℹ  About ")

        about = """
  DNS SPOOFING SIMULATOR
  ══════════════════════════════════════════════

  Module    : Ethical Hacking and Cyber Security
  Language  : Python 3 with Tkinter GUI
  Purpose   : Educational simulation of DNS cache poisoning / spoofing

  ──────────────────────────────────────────────
  WHAT IS DNS SPOOFING?
  ──────────────────────────────────────────────
  DNS (Domain Name System) spoofing, also called DNS cache poisoning,
  is a type of cyber attack where an attacker injects malicious DNS
  records into a resolver's cache, redirecting users to fraudulent
  IP addresses controlled by the attacker.

  When a victim queries a spoofed domain, they receive the attacker's
  IP instead of the legitimate server's address — silently redirecting
  web traffic, emails, or other network connections.

  ──────────────────────────────────────────────
  OOP DESIGN
  ──────────────────────────────────────────────
  • DNSRecord        — dataclass representing DNS entries
  • DNSQuery         — dataclass representing client queries
  • DNSCache         — LRU cache using OrderedDict
  • LegitimateResolver — simulated real DNS server
  • SpoofingEngine   — core attack/interception logic
  • DNSSpoofingSimulatorApp — Tkinter GUI application

  ──────────────────────────────────────────────
  DATA STRUCTURES USED
  ──────────────────────────────────────────────
  • OrderedDict  — LRU cache eviction policy
  • deque        — bounded query log (maxlen=200)
  • dict         — spoof table (O(1) lookup)
  • list         — domain database

  ──────────────────────────────────────────────
  ⚠  DISCLAIMER
  ──────────────────────────────────────────────
  This tool is for EDUCATIONAL PURPOSES ONLY.
  No real network packets are sent. All DNS resolution
  is simulated within the application.
  Using DNS spoofing on real networks without authorisation
  is illegal under the Computer Misuse Act 1990 and
  equivalent laws worldwide.
"""
        tk.Label(frame, text=about, bg=self.DARK_BG, fg=self.TEXT,
                 font=self.FONT_MONO, justify="left", anchor="nw").pack(fill="both", padx=20, pady=10)

    # ─── Helper: styled button ──────────────────

    def _btn(self, parent, text, cmd, color):
        return tk.Button(parent, text=text, command=cmd,
                         bg=color, fg="#000000", activebackground=color,
                         font=("Segoe UI", 9, "bold"), relief="flat",
                         padx=10, pady=4, cursor="hand2")

    # ─── Event Handlers ─────────────────────────

    def _toggle_spoofing(self):
        self.engine.active = self.attack_active_var.get()
        if self.engine.active:
            self.status_var.set("● Spoofing: ACTIVE  ⚠")
        else:
            self.status_var.set("● Spoofing: INACTIVE")
        self._update_stats()

    def _update_rate(self, _=None):
        self.engine.intercept_rate = self.rate_var.get()

    def _add_spoof_entry(self):
        domain = self.spoof_domain_var.get().strip()
        ip     = self.attacker_ip_var.get().strip()
        if not domain or not ip:
            messagebox.showwarning("Input Required", "Enter both domain and attacker IP.")
            return
        self.engine.add_spoof_entry(domain, ip)
        self.spoof_tree.insert("", "end", values=(domain, ip), tags=("spoof",))
        self.spoof_tree.tag_configure("spoof", foreground=self.RED)

    def _remove_spoof_entry(self):
        sel = self.spoof_tree.selection()
        if not sel:
            return
        for item in sel:
            domain = self.spoof_tree.item(item)["values"][0]
            self.engine.remove_spoof_entry(domain)
            self.spoof_tree.delete(item)

    def _clear_spoof_table(self):
        self.engine.clear_spoof_table()
        for item in self.spoof_tree.get_children():
            self.spoof_tree.delete(item)

    def _manual_query(self):
        domain = self.q_domain_var.get().strip()
        client = self.q_client_var.get().strip() or "127.0.0.1"
        if not domain:
            messagebox.showwarning("Input Required", "Enter a domain to resolve.")
            return
        query = self.engine.resolve(domain, client)
        self._display_query_result(query)
        self._update_stats()

    def _display_query_result(self, query: DNSQuery):
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("end", "─" * 52 + "\n", "header")
        self.result_text.insert("end",  " DNS RESOLUTION RESULT\n", "header")
        self.result_text.insert("end", "─" * 52 + "\n", "header")
        lines = [
            f"  Query ID   : {query.query_id}",
            f"  Timestamp  : {query.timestamp}",
            f"  Domain     : {query.domain}",
            f"  Client IP  : {query.client_ip}",
            f"  Resolved   : {query.resolved_ip}",
            f"  Status     : {query.status}",
            f"  Spoofed?   : {'YES ⚠' if query.spoofed else 'No ✔'}",
        ]
        for line in lines:
            tag = "spoof" if query.spoofed and "Spoofed" in line else ("legit" if not query.spoofed else "")
            self.result_text.insert("end", line + "\n", tag)
        self.result_text.insert("end", "─" * 52 + "\n", "header")
        if query.spoofed:
            self.result_text.insert("end",
                "\n  ⚠ ATTACK DETECTED: Client was redirected to\n"
                f"    attacker-controlled server: {query.resolved_ip}\n", "spoof")
        else:
            self.result_text.insert("end",
                "\n  ✔ Resolution is legitimate.\n", "legit")
        self.result_text.configure(state="disabled")

    def _refresh_log(self):
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        for q in self.engine.query_log:
            tag = "spoofed" if q.spoofed else ("cache" if q.status == "CACHE HIT" else "legit")
            self.log_tree.insert("", "end",
                values=(q.timestamp, q.query_id, q.domain, q.client_ip, q.resolved_ip, q.status),
                tags=(tag,))

    def _clear_log(self):
        self.engine.query_log.clear()
        self._refresh_log()

    def _refresh_cache(self):
        for item in self.cache_tree.get_children():
            self.cache_tree.delete(item)
        for r in self.engine.cache.all_records():
            is_spoofed = r.spoofed_ip != r.real_ip and r.real_ip != ""
            tag = "spoofed" if is_spoofed else "clean"
            self.cache_tree.insert("", "end",
                values=(r.domain, r.real_ip or "N/A", r.spoofed_ip,
                        "YES ⚠" if is_spoofed else "No", r.timestamp),
                tags=(tag,))

    def _flush_cache(self):
        self.engine.cache.clear()
        self._refresh_cache()

    def _update_stats(self):
        s = self.engine.statistics()
        self.stats_text.configure(state="normal")
        self.stats_text.delete("1.0", "end")
        self.stats_text.insert("end",
            f"  Total Queries : {s['total']}\n"
            f"  Spoofed       : {s['spoofed']}\n"
            f"  Legitimate    : {s['legitimate']}\n"
            f"  Spoof Rate    : {s['spoof_rate']}\n"
            f"  Cache Size    : {len(self.engine.cache)}\n"
            f"  Spoof Entries : {len(self.engine.spoofed_table)}\n"
            f"  Attack Active : {'YES' if self.engine.active else 'No'}\n"
        )
        self.stats_text.configure(state="disabled")

    # ── Simulation ──────────────────────────────

    def _start_simulation(self):
        if self.simulation_running:
            return
        self.simulation_running = True
        self._sim_thread = threading.Thread(target=self._sim_worker, daemon=True)
        self._sim_thread.start()

    def _stop_simulation(self):
        self.simulation_running = False

    def _sim_worker(self):
        domains = LegitimateResolver.all_domains()
        while self.simulation_running:
            domain = random.choice(domains)
            client = self.sim_client_var.get().strip() or "10.0.0.42"
            self.engine.resolve(domain, client)
            self.after(0, self._update_stats)
            self.after(0, self._refresh_log)
            time.sleep(random.uniform(0.4, 1.2))

    # ── Unit Tests ──────────────────────────────

    def _run_tests(self):
        self.test_output.configure(state="normal")
        self.test_output.delete("1.0", "end")
        self.test_output.insert("end", "Running unit tests...\n\n", "info")

        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        for cls in [TestDNSCache, TestSpoofingEngine, TestLegitimateResolver]:
            suite.addTests(loader.loadTestsFromTestCase(cls))

        stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=2)
        result = runner.run(suite)
        output = stream.getvalue()

        for line in output.splitlines():
            if " ... ok" in line or "OK" in line:
                self.test_output.insert("end", line + "\n", "pass")
            elif "FAIL" in line or "ERROR" in line:
                self.test_output.insert("end", line + "\n", "fail")
            else:
                self.test_output.insert("end", line + "\n", "info")

        summary = (f"\n{'─'*50}\n"
                   f"Tests run : {result.testsRun}\n"
                   f"Failures  : {len(result.failures)}\n"
                   f"Errors    : {len(result.errors)}\n"
                   f"Result    : {'✔ ALL PASSED' if result.wasSuccessful() else '✖ SOME FAILED'}\n")
        tag = "pass" if result.wasSuccessful() else "fail"
        self.test_output.insert("end", summary, tag)
        self.test_output.configure(state="disabled")


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app = DNSSpoofingSimulatorApp()
    app.mainloop()