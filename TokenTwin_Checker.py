# -*- coding: utf-8 -*-
"""
TokenTwin Checker v3.0  -  Dual Token BAC / IDOR Tester
Burp Suite Extension  |  Jython 2.7 compatible

New in v3:
  - Smart Filter: skips static assets, only tests IDOR-relevant endpoints
  - IDOR Pattern Detector: scores each URL, adds Risk column with matched pattern
  - Diff Viewer: click any row to see side-by-side body comparison
  - Filter bar: show only SAME / High-Risk results
  - Body storage: responses kept in memory for diff without re-requesting

Install:
  Extender > Options > Python Environment > jython-standalone-*.jar
  Extender > Extensions > Add > Type: Python > select this file
"""

# ── Burp API ──────────────────────────────────────────────────
from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController

# ── Swing / AWT ───────────────────────────────────────────────
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JCheckBox,
    JTable, JScrollPane, JComboBox, JSplitPane,
    JProgressBar, JFileChooser, JTextArea, JMenuItem,
    BorderFactory, SwingUtilities, JOptionPane, BoxLayout,
    JToggleButton, ButtonGroup
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder
from javax.swing.event import ListSelectionListener
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Color, Font, Dimension, FlowLayout, Cursor, GridLayout
)
from java.awt.event import ActionListener
from java.io import PrintWriter, FileWriter
from java.util import ArrayList

# ── stdlib ────────────────────────────────────────────────────
import hashlib
import re
import traceback
import threading
import difflib
import jarray


# ─────────────────────────────────────────────────────────────
#  Palette
# ─────────────────────────────────────────────────────────────
class P:
    BG_DARK   = Color(0x1E, 0x1E, 0x2E)
    BG_PANEL  = Color(0x28, 0x28, 0x3D)
    BG_FIELD  = Color(0x1C, 0x1C, 0x2C)
    ACCENT    = Color(0x74, 0xC7, 0xEC)
    ACCENT2   = Color(0xCB, 0xA6, 0xF7)
    TEXT      = Color(0xCD, 0xD6, 0xF4)
    DIM       = Color(0x78, 0x7B, 0x97)
    RED       = Color(0xF3, 0x8B, 0xA8)
    GREEN     = Color(0xA6, 0xE3, 0xA1)
    ORANGE    = Color(0xFA, 0xB3, 0x87)
    YELLOW    = Color(0xF9, 0xE2, 0xAF)
    BORDER    = Color(0x45, 0x47, 0x5A)
    BTN_SAVE  = Color(0x89, 0xDC, 0xEB)
    BTN_CLR   = Color(0xF3, 0x8B, 0xA8)
    BTN_EXP   = Color(0xA6, 0xE3, 0xA1)
    DIFF_ADD  = Color(0x1E, 0x3A, 0x1E)   # dark green bg for diff added
    DIFF_DEL  = Color(0x3A, 0x1E, 0x1E)   # dark red bg for diff removed


# ─────────────────────────────────────────────────────────────
#  Smart Filter
# ─────────────────────────────────────────────────────────────
# Extensions that are never interesting for BAC/IDOR
_STATIC_EXT = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip)(\?.*)?$',
    re.IGNORECASE
)

# URL patterns that suggest a specific resource ID is present
_IDOR_PATTERNS = [
    # numeric ID in path segment  e.g. /users/1234  /orders/3720719
    (r'/\d{2,}(?:/|$|\?)',          "Numeric ID in path",      "HIGH"),
    # UUID in path
    (r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/|$|\?)',
                                     "UUID in path",            "HIGH"),
    # common IDOR param names in query string
    (r'[?&](id|uid|user_id|account|account_id|order_id|ticket_id|invoice_id'
     r'|customer_id|file_id|doc_id|record_id|item_id|resource_id)=',
                                     "IDOR param in query",     "HIGH"),
    # numeric value in any query param  e.g. ?ref=9988
    (r'[?&][a-z_]+=\d{2,}',         "Numeric param value",     "MEDIUM"),
    # /me /self /account  (BAC without ID)
    (r'/(me|self|account|profile|dashboard|settings|preferences)(?:/|$|\?)',
                                     "Self-reference endpoint", "MEDIUM"),
    # /admin  /internal
    (r'/(admin|internal|manage|staff|superuser)(?:/|$|\?)',
                                     "Admin endpoint",          "HIGH"),
]
# Precompile
_IDOR_PATTERNS = [(re.compile(p, re.IGNORECASE), label, risk)
                   for p, label, risk in _IDOR_PATTERNS]

# Methods always worth testing (even without an ID pattern)
_INTERESTING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def smart_filter(method, url):
    """
    Returns (should_test, risk_level, pattern_label).
    risk_level: "HIGH" | "MEDIUM" | "LOW" | "SKIP"
    """
    # Always skip static assets
    path = url.split("?")[0]
    if _STATIC_EXT.search(path):
        return False, "SKIP", "Static asset"

    # Check IDOR patterns
    for pattern, label, risk in _IDOR_PATTERNS:
        if pattern.search(url):
            return True, risk, label

    # POST/PUT/PATCH/DELETE are always interesting even without an ID
    if method.upper() in _INTERESTING_METHODS:
        return True, "LOW", "Mutable method ({})".format(method.upper())

    # Plain GET with no ID pattern – low priority but still testable
    return True, "LOW", "Generic endpoint"


# ─────────────────────────────────────────────────────────────
#  Widget helpers
# ─────────────────────────────────────────────────────────────
def lbl(text, bold=False, size=12, color=None):
    w = JLabel(text)
    w.setFont(Font("Segoe UI", Font.BOLD if bold else Font.PLAIN, size))
    w.setForeground(color or P.TEXT)
    return w


def fld(cols=30):
    w = JTextField(cols)
    w.setBackground(P.BG_FIELD)
    w.setForeground(P.TEXT)
    w.setCaretColor(P.ACCENT)
    w.setFont(Font("Consolas", Font.PLAIN, 12))
    w.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(P.BORDER, 1),
        BorderFactory.createEmptyBorder(4, 8, 4, 8)
    ))
    return w


def mk_btn(text, bg):
    w = JButton(text)
    w.setBackground(bg)
    w.setForeground(Color(0x1E, 0x1E, 0x2E))
    w.setFont(Font("Segoe UI", Font.BOLD, 12))
    w.setFocusPainted(False)
    w.setBorderPainted(False)
    w.setOpaque(True)
    w.setCursor(Cursor(Cursor.HAND_CURSOR))
    return w


def mk_combo(items):
    w = JComboBox(items)
    w.setBackground(P.BG_FIELD)
    w.setForeground(P.TEXT)
    w.setFont(Font("Segoe UI", Font.PLAIN, 12))
    return w


def mk_cb(text):
    w = JCheckBox(text)
    w.setBackground(P.BG_PANEL)
    w.setForeground(P.TEXT)
    w.setFont(Font("Segoe UI", Font.PLAIN, 12))
    w.setFocusPainted(False)
    return w


# ─────────────────────────────────────────────────────────────
#  Table columns
#  0:#  1:Method  2:URL  3:Risk  4:Pattern  5:S1  6:L1  7:S2  8:L2  9:Result
# ─────────────────────────────────────────────────────────────
COLS = ["#", "Method", "URL", "Risk", "Pattern",
        "St.T1", "Len T1", "St.T2", "Len T2", "Result"]
COL_RISK    = 3
COL_PATTERN = 4
COL_RESULT  = 9


class ResultsModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self, COLS, 0)
    def isCellEditable(self, r, c):
        return False
    def getColumnClass(self, c):
        return type("")


# ─────────────────────────────────────────────────────────────
#  Cell renderer
# ─────────────────────────────────────────────────────────────
class ResultRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, tbl, val, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
                self, tbl, val, sel, foc, row, col)
        c.setBackground(P.BG_PANEL if row % 2 == 0 else P.BG_DARK)
        c.setForeground(P.TEXT)
        c.setFont(Font("Consolas", Font.PLAIN, 11))
        if sel:
            c.setBackground(P.BORDER)

        s = str(val) if val else ""

        if col == COL_RISK:
            if s == "HIGH":
                c.setForeground(P.RED)
                c.setFont(Font("Segoe UI", Font.BOLD, 11))
            elif s == "MEDIUM":
                c.setForeground(P.ORANGE)
                c.setFont(Font("Segoe UI", Font.BOLD, 11))
            elif s == "LOW":
                c.setForeground(P.DIM)
            else:
                c.setForeground(P.DIM)

        elif col == COL_RESULT:
            if "SAME" in s:
                c.setForeground(P.RED)
                c.setFont(Font("Segoe UI", Font.BOLD, 12))
            elif "Different" in s:
                c.setForeground(P.GREEN)
            elif "FILTERED" in s:
                c.setForeground(P.DIM)
            elif "ERROR" in s:
                c.setForeground(P.ORANGE)

        return c


# ─────────────────────────────────────────────────────────────
#  Background analysis thread
# ─────────────────────────────────────────────────────────────
class AnalysisThread(threading.Thread):

    def __init__(self, ext, messages, token1, token2,
                 tok_type, tok_name, ignore_pats, smart_filter_on,
                 model, msg_store, progress_bar, log_fn, on_done_fn):
        threading.Thread.__init__(self)
        self.daemon       = True
        self._ext         = ext
        self._msgs        = messages
        self._t1          = token1
        self._t2          = token2
        self._type        = tok_type
        self._name        = tok_name
        self._pats        = ignore_pats
        self._sf          = smart_filter_on
        self._model       = model
        self._store       = msg_store   # dict: row_num -> dict(svc, req1, resp1, req2, resp2)
        self._pb          = progress_bar
        self._log         = log_fn
        self._on_done     = on_done_fn
        self._counter     = [model.getRowCount() + 1]

    # ── response helpers ──────────────────────────────────────
    def _get_body_str(self, resp_bytes):
        if not resp_bytes:
            return ""
        info = self._ext.helpers.analyzeResponse(resp_bytes)
        body = self._ext.helpers.bytesToString(resp_bytes[info.getBodyOffset():])
        return body

    def _body_hash(self, body_str):
        if not body_str:
            return "EMPTY"
        s = body_str
        for p in self._pats:
            try:
                s = re.sub(p, "", s)
            except Exception:
                pass
        return hashlib.md5(s.encode("utf-8", errors="replace")).hexdigest()

    def _status(self, resp_bytes):
        if not resp_bytes:
            return 0
        return self._ext.helpers.analyzeResponse(resp_bytes).getStatusCode()

    def _body_len(self, resp_bytes):
        if not resp_bytes:
            return 0
        info = self._ext.helpers.analyzeResponse(resp_bytes)
        return len(resp_bytes) - info.getBodyOffset()

    # ── token injection ───────────────────────────────────────
    def _inject(self, req_bytes, svc, token):
        helpers  = self._ext.helpers
        info     = helpers.analyzeRequest(svc, req_bytes)
        headers  = list(info.getHeaders())
        body     = req_bytes[info.getBodyOffset():]
        name_lo  = self._name.lower()

        if self._type == "Header":
            new_hdrs = []
            replaced = False
            for h in headers:
                if h.lower().startswith(name_lo + ":"):
                    new_hdrs.append("{}: {}".format(self._name, token))
                    replaced = True
                else:
                    new_hdrs.append(h)
            if not replaced:
                new_hdrs.append("{}: {}".format(self._name, token))
            return helpers.buildHttpMessage(new_hdrs, body)

        else:  # Cookie
            new_hdrs     = []
            cookie_added = False
            for h in headers:
                if h.lower().startswith("cookie:"):
                    parts    = [x.strip() for x in h[7:].strip().split(";")]
                    new_ck   = []
                    replaced = False
                    for part in parts:
                        if "=" in part:
                            k, _, v = part.partition("=")
                            if k.strip().lower() == name_lo:
                                new_ck.append("{}={}".format(self._name, token))
                                replaced = True
                                continue
                        new_ck.append(part)
                    if not replaced:
                        new_ck.append("{}={}".format(self._name, token))
                    new_hdrs.append("Cookie: " + "; ".join(new_ck))
                    cookie_added = True
                else:
                    new_hdrs.append(h)
            if not cookie_added:
                new_hdrs.append("Cookie: {}={}".format(self._name, token))
            return helpers.buildHttpMessage(new_hdrs, body)

    def _send(self, svc, req_bytes):
        try:
            return self._ext.callbacks.makeHttpRequest(svc, req_bytes)
        except Exception as e:
            self._log("[!] Network error: {}".format(e))
            return None

    # ── EDT push helpers ──────────────────────────────────────
    def _add_row(self, row_data):
        self._model.addRow(row_data)

    def _set_progress(self, val, text):
        self._pb.setValue(val)
        self._pb.setString(text)

    # ── main loop ─────────────────────────────────────────────
    def run(self):
        total  = len(self._msgs)
        tested = 0
        skip_c = 0

        self._log("[*] Received {} request(s)".format(total))

        for idx, msg in enumerate(self._msgs):
            try:
                svc       = msg.getHttpService()
                req_bytes = msg.getRequest()
                info      = self._ext.helpers.analyzeRequest(svc, req_bytes)
                method    = info.getMethod()
                url       = str(info.getUrl())

                # ── Smart Filter ──────────────────────────
                should_test, risk, pattern = smart_filter(method, url)

                if self._sf and not should_test:
                    skip_c += 1
                    self._log("[~] SKIP  {} {}  ({})".format(method, url, pattern))
                    pct = int((idx + 1) / float(total) * 100)
                    SwingUtilities.invokeLater(
                        lambda v=pct, i=idx: self._set_progress(
                            v, "{}%  ({}/{})  skipped:{}".format(v, i+1, total, skip_c))
                    )
                    continue

                self._log("[>] TEST  {} {}  [{}]".format(method, url, risk))

                req1 = self._inject(req_bytes, svc, self._t1)
                req2 = self._inject(req_bytes, svc, self._t2)

                r1 = self._send(svc, req1)
                r2 = self._send(svc, req2)

                rb1 = r1.getResponse() if r1 else None
                rb2 = r2.getResponse() if r2 else None

                s1, s2     = self._status(rb1), self._status(rb2)
                l1, l2     = self._body_len(rb1), self._body_len(rb2)
                body1_str  = self._get_body_str(rb1)
                body2_str  = self._get_body_str(rb2)
                h1         = self._body_hash(body1_str)
                h2         = self._body_hash(body2_str)

                if s1 == s2 and h1 == h2:
                    result = "SAME - Possible BAC/IDOR"
                    self._log("  [!!] SAME  [{}]  {}".format(risk, url))
                else:
                    result = "Different"
                    self._log("  [+] Different (OK)")

                row_num = self._counter[0]
                self._counter[0] += 1
                tested  += 1

                # Store full request/response bytes for POC viewer
                self._store[row_num] = {
                    "svc":   svc,
                    "req1":  req1,
                    "resp1": rb1,
                    "req2":  req2,
                    "resp2": rb2,
                }

                row = [row_num, method, url, risk, pattern,
                       s1, l1, s2, l2, result]

                SwingUtilities.invokeLater(
                    lambda r=row: self._add_row(r)
                )

            except Exception:
                self._log("[!] Error on #{}: {}".format(
                    idx + 1, traceback.format_exc()))

            pct = int((idx + 1) / float(total) * 100)
            SwingUtilities.invokeLater(
                lambda v=pct, i=idx: self._set_progress(
                    v, "{}%  ({}/{})".format(v, i+1, total))
            )

        summary = "Done — tested:{} skipped:{} total:{}".format(
            tested, skip_c, total)
        SwingUtilities.invokeLater(
            lambda: self._set_progress(0, summary)
        )
        self._log("[*] " + summary)
        if self._on_done:
            SwingUtilities.invokeLater(self._on_done)


# ─────────────────────────────────────────────────────────────
#  Message editor controller
#  Required by Burp's native IMessageEditor (gives Repeater-style
#  rendering, syntax highlighting, "Pretty/Raw/Hex" tabs for free).
#  Each pane (Token1-Req, Token1-Resp, Token2-Req, Token2-Resp)
#  gets its own controller instance pointing at the stored bytes.
# ─────────────────────────────────────────────────────────────
class StaticMessageController(IMessageEditorController):
    """A controller that always returns a fixed, pre-stored message."""

    def __init__(self):
        self._svc  = None
        self._req  = None
        self._resp = None

    def set_data(self, svc, req_bytes, resp_bytes):
        self._svc  = svc
        self._req  = req_bytes
        self._resp = resp_bytes

    def getHttpService(self):
        return self._svc

    def getRequest(self):
        return self._req

    def getResponse(self):
        return self._resp


# ─────────────────────────────────────────────────────────────
#  Repeater-style PoC panel
#  Two side-by-side columns (Token 1 | Token 2), each with a
#  vertical split: Request on top, Response on bottom — exactly
#  like Burp Repeater — using Burp's own native message editors.
# ─────────────────────────────────────────────────────────────
class PocPanel(JPanel):

    def __init__(self, callbacks):
        JPanel.__init__(self, BorderLayout())
        self._callbacks = callbacks
        self.setBackground(P.BG_DARK)
        self.setBorder(EmptyBorder(2, 10, 8, 10))

        hdr = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        hdr.setBackground(P.BG_DARK)
        hdr.add(lbl("Proof of Concept", bold=True, size=12, color=P.DIM))
        hdr.add(lbl("  (click a row above to load Request/Response for both tokens)",
                    size=11, color=P.DIM))
        self.add(hdr, BorderLayout.NORTH)

        # Controllers hold the raw bytes that the editors read from
        self._ctrl_req1  = StaticMessageController()
        self._ctrl_resp1 = StaticMessageController()
        self._ctrl_req2  = StaticMessageController()
        self._ctrl_resp2 = StaticMessageController()

        # Native Burp message editors (read-only)
        self._editor_req1  = callbacks.createMessageEditor(self._ctrl_req1,  False)
        self._editor_resp1 = callbacks.createMessageEditor(self._ctrl_resp1, False)
        self._editor_req2  = callbacks.createMessageEditor(self._ctrl_req2,  False)
        self._editor_resp2 = callbacks.createMessageEditor(self._ctrl_resp2, False)

        col1 = self._make_column("Token 1", self._editor_req1, self._editor_resp1, P.ACCENT)
        col2 = self._make_column("Token 2", self._editor_req2, self._editor_resp2, P.ACCENT2)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, col1, col2)
        split.setResizeWeight(0.5)
        split.setBackground(P.BG_DARK)
        split.setBorder(None)
        split.setDividerSize(4)
        self.add(split, BorderLayout.CENTER)

    def _make_column(self, title, req_editor, resp_editor, accent):
        outer = JPanel(BorderLayout())
        outer.setBackground(P.BG_DARK)

        title_p = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        title_p.setBackground(P.BG_PANEL)
        title_p.add(lbl(title, bold=True, size=12, color=accent))
        outer.add(title_p, BorderLayout.NORTH)

        req_panel  = self._wrap("Request",  req_editor.getComponent())
        resp_panel = self._wrap("Response", resp_editor.getComponent())

        vsplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, req_panel, resp_panel)
        vsplit.setResizeWeight(0.5)
        vsplit.setBackground(P.BG_DARK)
        vsplit.setBorder(None)
        vsplit.setDividerSize(4)
        outer.add(vsplit, BorderLayout.CENTER)
        return outer

    def _wrap(self, title, component):
        p = JPanel(BorderLayout())
        p.setBackground(P.BG_DARK)
        hdr = JPanel(FlowLayout(FlowLayout.LEFT, 4, 1))
        hdr.setBackground(P.BG_PANEL)
        hdr.add(lbl(title, bold=True, size=10, color=P.TEXT))
        p.add(hdr, BorderLayout.NORTH)
        p.add(component, BorderLayout.CENTER)
        p.setBorder(BorderFactory.createLineBorder(P.BORDER, 1))
        return p

    def show_poc(self, svc, req1, resp1, req2, resp2):
        """Call from EDT only. Any of req/resp may be None."""
        empty = jarray.array([], "b")

        self._ctrl_req1.set_data(svc, req1, None)
        self._ctrl_resp1.set_data(svc, req1, resp1)
        self._ctrl_req2.set_data(svc, req2, None)
        self._ctrl_resp2.set_data(svc, req2, resp2)

        self._editor_req1.setMessage(req1 if req1 else empty, True)
        self._editor_resp1.setMessage(resp1 if resp1 else empty, False)
        self._editor_req2.setMessage(req2 if req2 else empty, True)
        self._editor_resp2.setMessage(resp2 if resp2 else empty, False)

    def clear(self):
        empty = jarray.array([], "b")
        self._editor_req1.setMessage(empty, True)
        self._editor_resp1.setMessage(empty, False)
        self._editor_req2.setMessage(empty, True)
        self._editor_resp2.setMessage(empty, False)


# ─────────────────────────────────────────────────────────────
#  Main extension
# ─────────────────────────────────────────────────────────────
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("TokenTwin Checker")

        self._stdout   = PrintWriter(callbacks.getStdout(), True)
        self._log("TokenTwin Checker v3.0 loaded")

        # msg_store: row_number -> dict(svc, req1, resp1, req2, resp2)
        self._msg_store = {}

        self._ui_ready = threading.Event()
        SwingUtilities.invokeLater(self._build_ui)
        self._ui_ready.wait(5)

        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    # ── ITab ─────────────────────────────────────────────────
    def getTabCaption(self):
        return "TokenTwin"

    def getUiComponent(self):
        return self._root

    # ── IContextMenuFactory ───────────────────────────────────
    def createMenuItems(self, inv):
        try:
            msgs = inv.getSelectedMessages()
        except Exception:
            msgs = None
        if not msgs:
            return ArrayList()

        item = JMenuItem("Send to TokenTwin Checker")

        class _L(ActionListener):
            def actionPerformed(_self, e):
                self._enqueue(list(msgs))

        item.addActionListener(_L())
        out = ArrayList()
        out.add(item)
        return out

    # ── Logging ───────────────────────────────────────────────
    def _log(self, msg):
        self._stdout.println(msg)
        if hasattr(self, "_log_area"):
            def _do():
                self._log_area.append(msg + "\n")
                doc = self._log_area.getDocument()
                self._log_area.setCaretPosition(doc.getLength())
            SwingUtilities.invokeLater(_do)

    # ─────────────────────────────────────────────────────────
    #  UI build
    # ─────────────────────────────────────────────────────────
    def _build_ui(self):
        self._root = JPanel(BorderLayout())
        self._root.setBackground(P.BG_DARK)
        self._root.add(self._make_banner(), BorderLayout.NORTH)

        # Top: config
        # Middle: table
        # Bottom: diff viewer + log  (split)
        top_split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            self._make_config_panel(),
            self._make_center_split()
        )
        top_split.setDividerLocation(185)
        top_split.setResizeWeight(0.0)
        top_split.setBackground(P.BG_DARK)
        top_split.setBorder(None)
        self._root.add(top_split, BorderLayout.CENTER)
        self._ui_ready.set()

    # ── Banner ────────────────────────────────────────────────
    def _make_banner(self):
        p = JPanel(FlowLayout(FlowLayout.LEFT, 16, 8))
        p.setBackground(P.BG_PANEL)
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, P.BORDER))
        p.add(lbl("TokenTwin Checker", bold=True, size=18, color=P.ACCENT))
        p.add(lbl("|", color=P.BORDER))
        p.add(lbl("v3.0  |  BAC / IDOR Hunter", size=12, color=P.DIM))
        return p

    # ── Config panel ──────────────────────────────────────────
    def _make_config_panel(self):
        outer = JPanel(BorderLayout())
        outer.setBackground(P.BG_DARK)
        outer.setBorder(EmptyBorder(8, 10, 4, 10))

        inner = JPanel(GridBagLayout())
        inner.setBackground(P.BG_PANEL)
        inner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(P.BORDER, 1),
            EmptyBorder(10, 14, 10, 14)
        ))

        g = GridBagConstraints()
        g.insets = Insets(4, 5, 4, 5)
        g.fill   = GridBagConstraints.HORIZONTAL
        g.anchor = GridBagConstraints.WEST

        # Row 0 — token type + name
        g.gridx, g.gridy, g.gridwidth = 0, 0, 1
        inner.add(lbl("Type:", bold=True), g)
        g.gridx = 1
        self._type_combo = mk_combo(["Header", "Cookie"])
        inner.add(self._type_combo, g)
        g.gridx = 2
        inner.add(lbl("Name:", bold=True), g)
        g.gridx = 3; g.gridwidth = 3
        self._name_field = fld(22)
        self._name_field.setText("Authorization")
        inner.add(self._name_field, g)

        # Row 1 — Token 1
        g.gridx, g.gridy, g.gridwidth = 0, 1, 1
        inner.add(lbl("Token 1:", bold=True, color=P.ACCENT), g)
        g.gridx = 1; g.gridwidth = 5
        self._t1_field = fld(60)
        inner.add(self._t1_field, g)

        # Row 2 — Token 2
        g.gridx, g.gridy, g.gridwidth = 0, 2, 1
        inner.add(lbl("Token 2:", bold=True, color=P.ACCENT2), g)
        g.gridx = 1; g.gridwidth = 5
        self._t2_field = fld(60)
        inner.add(self._t2_field, g)

        # Row 3 — Ignore patterns + smart filter toggle
        g.gridx, g.gridy, g.gridwidth = 0, 3, 1
        inner.add(lbl("Ignore regex:", bold=True), g)
        g.gridx = 1; g.gridwidth = 3
        self._ignore_field = fld(40)
        self._ignore_field.setText('"nonce":"[^"]*"|"timestamp":\\d+')
        self._ignore_field.setToolTipText(
            "Pipe-separated regex patterns stripped from body before hash comparison")
        inner.add(self._ignore_field, g)

        g.gridx = 4; g.gridwidth = 2
        self._sf_cb = mk_cb("Smart Filter (skip static/irrelevant)")
        self._sf_cb.setSelected(True)
        inner.add(self._sf_cb, g)

        # Row 4 — buttons + progress
        g.gridx, g.gridy, g.gridwidth = 0, 4, 1

        b_save = mk_btn("Save Tokens", P.BTN_SAVE)
        b_clr  = mk_btn("Clear All",   P.BTN_CLR)
        b_exp  = mk_btn("Export CSV",  P.BTN_EXP)

        class _Save(ActionListener):
            def actionPerformed(_s, e): self._save_tokens()
        class _Clr(ActionListener):
            def actionPerformed(_s, e):
                self._model.setRowCount(0)
                self._msg_store.clear()
                self._poc_panel.clear()
                self._log("[*] Results cleared.")
        class _Exp(ActionListener):
            def actionPerformed(_s, e): self._export_csv()

        b_save.addActionListener(_Save())
        b_clr.addActionListener(_Clr())
        b_exp.addActionListener(_Exp())

        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        btn_row.setBackground(P.BG_PANEL)
        btn_row.add(b_save)
        btn_row.add(b_clr)
        btn_row.add(b_exp)
        g.gridwidth = 6
        inner.add(btn_row, g)

        # Row 5 — progress bar
        g.gridx, g.gridy, g.gridwidth = 0, 5, 6
        self._pb = JProgressBar(0, 100)
        self._pb.setStringPainted(True)
        self._pb.setString("Ready")
        self._pb.setBackground(P.BG_FIELD)
        self._pb.setForeground(P.ACCENT)
        self._pb.setBorder(BorderFactory.createLineBorder(P.BORDER, 1))
        self._pb.setPreferredSize(Dimension(0, 18))
        inner.add(self._pb, g)

        outer.add(inner, BorderLayout.CENTER)
        return outer

    # ── Center: table | (diff + log) ─────────────────────────
    def _make_center_split(self):
        bottom = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            self._make_poc_panel(),
            self._make_log_panel()
        )
        bottom.setDividerLocation(420)
        bottom.setResizeWeight(0.85)
        bottom.setBackground(P.BG_DARK)
        bottom.setBorder(None)

        mid = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            self._make_table_panel(),
            bottom
        )
        mid.setDividerLocation(220)
        mid.setResizeWeight(0.3)
        mid.setBackground(P.BG_DARK)
        mid.setBorder(None)
        return mid

    # ── Results table ─────────────────────────────────────────
    def _make_table_panel(self):
        p = JPanel(BorderLayout())
        p.setBackground(P.BG_DARK)
        p.setBorder(EmptyBorder(4, 10, 2, 10))

        # Header row with filter buttons
        hdr = JPanel(FlowLayout(FlowLayout.LEFT, 8, 3))
        hdr.setBackground(P.BG_DARK)
        hdr.add(lbl("Results", bold=True, size=13, color=P.ACCENT))
        hdr.add(lbl("  Filter:", size=11, color=P.DIM))

        self._filter_all      = self._filter_btn("All")
        self._filter_same     = self._filter_btn("SAME only")
        self._filter_high     = self._filter_btn("HIGH risk only")

        class _FA(ActionListener):
            def actionPerformed(_s, e): self._apply_filter("all")
        class _FS(ActionListener):
            def actionPerformed(_s, e): self._apply_filter("same")
        class _FH(ActionListener):
            def actionPerformed(_s, e): self._apply_filter("high")

        self._filter_all.addActionListener(_FA())
        self._filter_same.addActionListener(_FS())
        self._filter_high.addActionListener(_FH())
        self._active_filter = "all"

        hdr.add(self._filter_all)
        hdr.add(self._filter_same)
        hdr.add(self._filter_high)
        p.add(hdr, BorderLayout.NORTH)

        self._model = ResultsModel()
        self._table = JTable(self._model)
        self._table.setBackground(P.BG_PANEL)
        self._table.setForeground(P.TEXT)
        self._table.setGridColor(P.BORDER)
        self._table.setRowHeight(24)
        self._table.setFont(Font("Consolas", Font.PLAIN, 11))
        self._table.setSelectionBackground(P.BORDER)
        self._table.setFillsViewportHeight(True)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self._table.setSelectionMode(
            javax.swing.ListSelectionModel.SINGLE_SELECTION)

        th = self._table.getTableHeader()
        th.setBackground(P.BG_DARK)
        th.setForeground(P.ACCENT)
        th.setFont(Font("Segoe UI", Font.BOLD, 11))

        rr = ResultRenderer()
        cm = self._table.getColumnModel()
        for i in range(len(COLS)):
            cm.getColumn(i).setCellRenderer(rr)

        for i, w in enumerate([30, 58, 280, 55, 160, 52, 52, 52, 52, 175]):
            cm.getColumn(i).setPreferredWidth(w)

        # Row selection → POC viewer
        ext_ref = self

        class _Sel(ListSelectionListener):
            def valueChanged(_self, e):
                if e.getValueIsAdjusting():
                    return
                view_row = ext_ref._table.getSelectedRow()
                if view_row < 0:
                    return
                # Convert view row to model row (RowSorter may be filtering/sorting)
                try:
                    model_row = ext_ref._table.convertRowIndexToModel(view_row)
                except Exception:
                    model_row = view_row
                row_num = ext_ref._model.getValueAt(model_row, 0)
                try:
                    row_num = int(str(row_num))
                except Exception:
                    return
                data = ext_ref._msg_store.get(row_num)
                if data:
                    ext_ref._poc_panel.show_poc(
                        data["svc"], data["req1"], data["resp1"],
                        data["req2"], data["resp2"]
                    )

        self._table.getSelectionModel().addListSelectionListener(_Sel())

        sc = JScrollPane(self._table)
        sc.getViewport().setBackground(P.BG_PANEL)
        sc.setBorder(BorderFactory.createLineBorder(P.BORDER, 1))
        p.add(sc, BorderLayout.CENTER)
        return p

    def _filter_btn(self, text):
        b = JButton(text)
        b.setBackground(P.BG_FIELD)
        b.setForeground(P.TEXT)
        b.setFont(Font("Segoe UI", Font.PLAIN, 11))
        b.setFocusPainted(False)
        b.setBorderPainted(True)
        b.setOpaque(True)
        b.setCursor(Cursor(Cursor.HAND_CURSOR))
        b.setBorder(BorderFactory.createLineBorder(P.BORDER, 1))
        return b

    def _apply_filter(self, mode):
        self._active_filter = mode
        # Highlight active button
        for b, m in [(self._filter_all,  "all"),
                     (self._filter_same, "same"),
                     (self._filter_high, "high")]:
            if m == mode:
                b.setBackground(P.ACCENT)
                b.setForeground(Color(0x1E, 0x1E, 0x2E))
            else:
                b.setBackground(P.BG_FIELD)
                b.setForeground(P.TEXT)

        # Hide rows not matching filter by adjusting row visibility
        # JTable has no native row hiding – we use RowFilter via TableRowSorter
        # But to keep Jython-safe, we rebuild a view model instead.
        # Simple approach: use row sorter with RowFilter
        import javax.swing.table as jst
        import javax.swing as jsw

        sorter = jst.TableRowSorter(self._model)
        self._table.setRowSorter(sorter)

        if mode == "all":
            sorter.setRowFilter(None)
        elif mode == "same":
            class _F(jst.RowFilter):
                def include(_self, entry):
                    v = str(entry.getValue(COL_RESULT) or "")
                    return "SAME" in v
            sorter.setRowFilter(_F())
        elif mode == "high":
            class _F2(jst.RowFilter):
                def include(_self, entry):
                    risk   = str(entry.getValue(COL_RISK) or "")
                    result = str(entry.getValue(COL_RESULT) or "")
                    return risk == "HIGH" and "SAME" in result
            sorter.setRowFilter(_F2())

    # ── POC panel ─────────────────────────────────────────────
    def _make_poc_panel(self):
        self._poc_panel = PocPanel(self.callbacks)
        return self._poc_panel

    # ── Log panel ─────────────────────────────────────────────
    def _make_log_panel(self):
        p = JPanel(BorderLayout())
        p.setBackground(P.BG_DARK)
        p.setBorder(EmptyBorder(2, 10, 6, 10))

        hdr = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        hdr.setBackground(P.BG_DARK)
        hdr.add(lbl("Activity Log", bold=True, size=11, color=P.DIM))
        p.add(hdr, BorderLayout.NORTH)

        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setBackground(P.BG_DARK)
        self._log_area.setForeground(P.DIM)
        self._log_area.setFont(Font("Consolas", Font.PLAIN, 11))
        self._log_area.setLineWrap(True)
        self._log_area.setWrapStyleWord(True)
        self._log_area.setBorder(EmptyBorder(4, 8, 4, 8))

        sc = JScrollPane(self._log_area)
        sc.getViewport().setBackground(P.BG_DARK)
        sc.setBorder(BorderFactory.createLineBorder(P.BORDER, 1))
        p.add(sc, BorderLayout.CENTER)
        return p

    # ─────────────────────────────────────────────────────────
    #  Actions
    # ─────────────────────────────────────────────────────────
    def _save_tokens(self):
        t1 = self._t1_field.getText().strip()
        t2 = self._t2_field.getText().strip()
        if not t1 or not t2:
            JOptionPane.showMessageDialog(
                self._root, "Both tokens must be filled in.",
                "Missing Tokens", JOptionPane.WARNING_MESSAGE)
            return
        n = self._name_field.getText().strip()
        self._log("[*] Tokens saved  |  Type:{}  Name:{}".format(
            self._type_combo.getSelectedItem(), n or "(empty)"))
        JOptionPane.showMessageDialog(
            self._root,
            "Tokens saved.\n\nRight-click any request and choose\n"
            "\"Send to TokenTwin Checker\" to test.",
            "Saved", JOptionPane.INFORMATION_MESSAGE)

    def _get_ignore_pats(self):
        raw = self._ignore_field.getText().strip()
        return [x.strip() for x in raw.split("|") if x.strip()] if raw else []

    def _enqueue(self, messages):
        t1 = self._t1_field.getText().strip()
        t2 = self._t2_field.getText().strip()
        if not t1 or not t2:
            JOptionPane.showMessageDialog(
                self._root, "Please fill in both tokens first.",
                "Tokens Not Set", JOptionPane.WARNING_MESSAGE)
            return

        tok_type = str(self._type_combo.getSelectedItem())
        tok_name = self._name_field.getText().strip()
        if not tok_name:
            tok_name = "Authorization" if tok_type == "Header" else "session"

        def _after_done():
            self._apply_filter(self._active_filter)

        t = AnalysisThread(
            ext           = self,
            messages      = messages,
            token1        = t1,
            token2        = t2,
            tok_type      = tok_type,
            tok_name      = tok_name,
            ignore_pats   = self._get_ignore_pats(),
            smart_filter_on = self._sf_cb.isSelected(),
            model         = self._model,
            msg_store     = self._msg_store,
            progress_bar  = self._pb,
            log_fn        = self._log,
            on_done_fn    = _after_done
        )
        self._pb.setValue(0)
        self._pb.setString("Starting...")
        t.start()

    def _export_csv(self):
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Results as CSV")
        if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".csv"):
            path += ".csv"
        try:
            w = FileWriter(path)
            w.write(",".join(COLS) + "\n")
            for r in range(self._model.getRowCount()):
                vals = []
                for c in range(self._model.getColumnCount()):
                    v = str(self._model.getValueAt(r, c) or "")
                    vals.append('"{}"'.format(v.replace('"', '""')))
                w.write(",".join(vals) + "\n")
            w.close()
            self._log("[*] Exported: {}".format(path))
            JOptionPane.showMessageDialog(
                self._root, "Exported to:\n" + path,
                "Export Done", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self._log("[!] Export error: {}".format(e))
            JOptionPane.showMessageDialog(
                self._root, "Export failed:\n" + str(e),
                "Error", JOptionPane.ERROR_MESSAGE)


# need for RowFilter in _apply_filter
import javax.swing
