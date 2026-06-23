# -*- coding: utf-8 -*-
"""
TokenTwin Checker v4.0  -  Multi-User BAC / IDOR Tester
Burp Suite Extension  |  Jython 2.7 compatible

New in v4:
  - Multi-User: Add/remove unlimited users, each with their own token
  - Header Manager: Replace the old Type/Name combo with a full per-user
    header table (Key: Value rows). Cookies are just headers — add a
    "Cookie" row with "session=abc; other=xyz" value.
  - Multiple headers per user (e.g. Authorization + X-User-ID + Cookie)
  - Baseline User: designate one user as the "owner/attacker" baseline;
    all other users are tested against it
  - Comparison Mode: "All vs Baseline" or "All vs All"
  - Dynamic result columns: columns scale with user count
  - Per-user color coding in POC viewer
  - Profile Import/Export: save/load user sets as JSON
  - Smart Filter, IDOR Pattern Detector, Diff Viewer — all preserved

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
    JToggleButton, ButtonGroup, JTabbedPane, JToolBar,
    ScrollPaneConstants, DefaultListModel, JList,
    ListSelectionModel
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder
from javax.swing.event import ListSelectionListener
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Color, Font, Dimension, FlowLayout, Cursor, GridLayout,
    CardLayout
)
from java.awt.event import ActionListener, FocusAdapter
from java.io import PrintWriter, FileWriter, FileReader, BufferedReader
from java.util import ArrayList

# ── stdlib ────────────────────────────────────────────────────
import hashlib
import re
import traceback
import threading
import difflib
import jarray
import json
import os


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
    BTN_ADD   = Color(0xA6, 0xE3, 0xA1)
    BTN_DEL   = Color(0xF3, 0x8B, 0xA8)
    BTN_IMP   = Color(0xF9, 0xE2, 0xAF)
    DIFF_ADD  = Color(0x1E, 0x3A, 0x1E)
    DIFF_DEL  = Color(0x3A, 0x1E, 0x1E)

    # Per-user accent colors (cycles if > len)
    USER_COLORS = [
        Color(0x74, 0xC7, 0xEC),   # blue
        Color(0xCB, 0xA6, 0xF7),   # purple
        Color(0xA6, 0xE3, 0xA1),   # green
        Color(0xFA, 0xB3, 0x87),   # orange
        Color(0xF9, 0xE2, 0xAF),   # yellow
        Color(0xF3, 0x8B, 0xA8),   # red
        Color(0x89, 0xDC, 0xEB),   # cyan
        Color(0xB4, 0xBE, 0xFE),   # lavender
    ]

    @staticmethod
    def user_color(idx):
        return P.USER_COLORS[idx % len(P.USER_COLORS)]


# ─────────────────────────────────────────────────────────────
#  Smart Filter
# ─────────────────────────────────────────────────────────────
_STATIC_EXT = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip)(\?.*)?$',
    re.IGNORECASE
)

_IDOR_PATTERNS = [
    (r'/\d{2,}(?:/|$|\?)',          "Numeric ID in path",      "HIGH"),
    (r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/|$|\?)',
                                     "UUID in path",            "HIGH"),
    (r'[?&](id|uid|user_id|account|account_id|order_id|ticket_id|invoice_id'
     r'|customer_id|file_id|doc_id|record_id|item_id|resource_id)=',
                                     "IDOR param in query",     "HIGH"),
    (r'[?&][a-z_]+=\d{2,}',         "Numeric param value",     "MEDIUM"),
    (r'/(me|self|account|profile|dashboard|settings|preferences)(?:/|$|\?)',
                                     "Self-reference endpoint", "MEDIUM"),
    (r'/(admin|internal|manage|staff|superuser)(?:/|$|\?)',
                                     "Admin endpoint",          "HIGH"),
]
_IDOR_PATTERNS = [(re.compile(p, re.IGNORECASE), label, risk)
                   for p, label, risk in _IDOR_PATTERNS]

_INTERESTING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def smart_filter(method, url):
    path = url.split("?")[0]
    if _STATIC_EXT.search(path):
        return False, "SKIP", "Static asset"
    for pattern, label, risk in _IDOR_PATTERNS:
        if pattern.search(url):
            return True, risk, label
    if method.upper() in _INTERESTING_METHODS:
        return True, "LOW", "Mutable method ({})".format(method.upper())
    return True, "LOW", "Generic endpoint"


# ─────────────────────────────────────────────────────────────
#  User Profile model
# ─────────────────────────────────────────────────────────────
class UserProfile(object):
    """Represents one test user: a label + ordered list of (key, value) headers."""

    def __init__(self, label="User", headers=None, is_baseline=False):
        self.label       = label
        # headers: list of [key, value] pairs
        self.headers     = headers if headers is not None else [["Authorization", ""]]
        self.is_baseline = is_baseline

    def to_dict(self):
        return {
            "label":       self.label,
            "headers":     self.headers,
            "is_baseline": self.is_baseline,
        }

    @staticmethod
    def from_dict(d):
        return UserProfile(
            label       = d.get("label", "User"),
            headers     = d.get("headers", [["Authorization", ""]]),
            is_baseline = d.get("is_baseline", False),
        )

    def clone(self):
        import copy
        return UserProfile(self.label, copy.deepcopy(self.headers), self.is_baseline)


# ─────────────────────────────────────────────────────────────
#  Widget helpers
# ─────────────────────────────────────────────────────────────
def lbl(text, bold=False, size=12, color=None):
    w = JLabel(text)
    w.setFont(Font("Segoe UI", Font.BOLD if bold else Font.PLAIN, size))
    w.setForeground(color or P.TEXT)
    return w


def fld(cols=30, text=""):
    w = JTextField(cols)
    w.setText(text)
    w.setBackground(P.BG_FIELD)
    w.setForeground(P.TEXT)
    w.setCaretColor(P.ACCENT)
    w.setFont(Font("Consolas", Font.PLAIN, 12))
    w.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(P.BORDER, 1),
        BorderFactory.createEmptyBorder(4, 8, 4, 8)
    ))
    return w


def mk_btn(text, bg, fg=None):
    w = JButton(text)
    w.setBackground(bg)
    w.setForeground(fg or Color(0x1E, 0x1E, 0x2E))
    w.setFont(Font("Segoe UI", Font.BOLD, 11))
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


def mk_sep():
    """Vertical separator panel."""
    p = JPanel()
    p.setBackground(P.BORDER)
    p.setPreferredSize(Dimension(1, 20))
    return p


# ─────────────────────────────────────────────────────────────
#  Header table model
#  Two columns: "Header Name" | "Value"
# ─────────────────────────────────────────────────────────────
class HeaderTableModel(DefaultTableModel):
    HDR_COLS = ["Header Name", "Value"]

    def __init__(self, rows=None):
        DefaultTableModel.__init__(self, self.HDR_COLS, 0)
        if rows:
            for r in rows:
                self.addRow(r)

    def isCellEditable(self, r, c):
        return True   # allow inline editing

    def get_pairs(self):
        """Return list of [name, value] from current rows (skip blank names)."""
        pairs = []
        for r in range(self.getRowCount()):
            name  = str(self.getValueAt(r, 0) or "").strip()
            value = str(self.getValueAt(r, 1) or "").strip()
            if name:
                pairs.append([name, value])
        return pairs

    def load_pairs(self, pairs):
        self.setRowCount(0)
        for p in pairs:
            self.addRow(p)


# ─────────────────────────────────────────────────────────────
#  Per-user header editor panel
# ─────────────────────────────────────────────────────────────
class UserHeaderPanel(JPanel):
    """
    A compact panel showing:
      - Label field
      - Header table (Name | Value) with Add/Remove row buttons
      - [Baseline] toggle
    """

    def __init__(self, profile, color, on_baseline_cb=None):
        JPanel.__init__(self, BorderLayout(0, 4))
        self.setBackground(P.BG_PANEL)
        self.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(color, 2),
            EmptyBorder(6, 8, 6, 8)
        ))
        self._color           = color
        self._profile         = profile
        self._on_baseline_cb  = on_baseline_cb

        # ── Top bar: label + baseline badge ──────────────────
        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        top.setBackground(P.BG_PANEL)
        top.add(lbl("Label:", bold=True, size=11, color=color))
        self._label_fld = fld(12, profile.label)
        self._label_fld.setFont(Font("Segoe UI", Font.BOLD, 11))
        top.add(self._label_fld)

        self._baseline_btn = JToggleButton("Baseline")
        self._baseline_btn.setSelected(profile.is_baseline)
        self._baseline_btn.setFont(Font("Segoe UI", Font.BOLD, 10))
        self._baseline_btn.setBackground(P.ACCENT if profile.is_baseline else P.BG_FIELD)
        self._baseline_btn.setForeground(Color(0x1E, 0x1E, 0x2E) if profile.is_baseline else P.DIM)
        self._baseline_btn.setFocusPainted(False)
        self._baseline_btn.setBorderPainted(True)
        self._baseline_btn.setOpaque(True)
        self._baseline_btn.setToolTipText(
            "Mark this user as the Baseline (owner). Others are tested against it.")

        ext = self
        class _BL(ActionListener):
            def actionPerformed(_s, e):
                if ext._on_baseline_cb:
                    ext._on_baseline_cb(ext)
        self._baseline_btn.addActionListener(_BL())
        top.add(self._baseline_btn)
        self.add(top, BorderLayout.NORTH)

        # ── Header table ─────────────────────────────────────
        self._hdr_model = HeaderTableModel(list(profile.headers))
        self._hdr_table = JTable(self._hdr_model)
        self._hdr_table.setBackground(P.BG_FIELD)
        self._hdr_table.setForeground(P.TEXT)
        self._hdr_table.setGridColor(P.BORDER)
        self._hdr_table.setRowHeight(22)
        self._hdr_table.setFont(Font("Consolas", Font.PLAIN, 11))
        self._hdr_table.setSelectionBackground(P.BORDER)
        self._hdr_table.getTableHeader().setBackground(P.BG_DARK)
        self._hdr_table.getTableHeader().setForeground(color)
        self._hdr_table.getTableHeader().setFont(Font("Segoe UI", Font.BOLD, 10))
        self._hdr_table.getColumnModel().getColumn(0).setPreferredWidth(140)
        self._hdr_table.getColumnModel().getColumn(1).setPreferredWidth(280)

        sc = JScrollPane(self._hdr_table)
        sc.setPreferredSize(Dimension(0, 90))
        sc.getViewport().setBackground(P.BG_FIELD)
        sc.setBorder(BorderFactory.createLineBorder(P.BORDER, 1))
        self.add(sc, BorderLayout.CENTER)

        # ── Row buttons ──────────────────────────────────────
        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        btn_row.setBackground(P.BG_PANEL)

        b_add_hdr  = mk_btn("+ Header", P.BTN_ADD)
        b_add_ck   = mk_btn("+ Cookie", P.BTN_IMP)
        b_del_row  = mk_btn("- Remove", P.BTN_DEL)
        b_add_hdr.setToolTipText("Add a new header row")
        b_add_ck.setToolTipText("Add a Cookie header row")
        b_del_row.setToolTipText("Remove the selected row")

        class _AddHdr(ActionListener):
            def actionPerformed(_s, e):
                ext._hdr_model.addRow(["", ""])
                r = ext._hdr_model.getRowCount() - 1
                ext._hdr_table.setRowSelectionInterval(r, r)
                ext._hdr_table.editCellAt(r, 0)

        class _AddCk(ActionListener):
            def actionPerformed(_s, e):
                ext._hdr_model.addRow(["Cookie", ""])
                r = ext._hdr_model.getRowCount() - 1
                ext._hdr_table.setRowSelectionInterval(r, r)
                ext._hdr_table.editCellAt(r, 1)

        class _Del(ActionListener):
            def actionPerformed(_s, e):
                sel = ext._hdr_table.getSelectedRow()
                if sel >= 0 and ext._hdr_model.getRowCount() > 1:
                    ext._hdr_model.removeRow(sel)

        b_add_hdr.addActionListener(_AddHdr())
        b_add_ck.addActionListener(_AddCk())
        b_del_row.addActionListener(_Del())

        btn_row.add(b_add_hdr)
        btn_row.add(b_add_ck)
        btn_row.add(b_del_row)
        self.add(btn_row, BorderLayout.SOUTH)

    def set_baseline(self, is_bl):
        self._baseline_btn.setSelected(is_bl)
        self._baseline_btn.setBackground(P.ACCENT if is_bl else P.BG_FIELD)
        self._baseline_btn.setForeground(
            Color(0x1E, 0x1E, 0x2E) if is_bl else P.DIM)

    def get_profile(self):
        """Return a UserProfile reflecting current UI state."""
        # Stop any active cell editing first
        if self._hdr_table.isEditing():
            self._hdr_table.getCellEditor().stopCellEditing()
        p = UserProfile(
            label       = self._label_fld.getText().strip() or "User",
            headers     = self._hdr_model.get_pairs(),
            is_baseline = self._baseline_btn.isSelected(),
        )
        return p


# ─────────────────────────────────────────────────────────────
#  Multi-user configuration panel
# ─────────────────────────────────────────────────────────────
class UserManagerPanel(JPanel):
    """
    Scrollable list of UserHeaderPanel widgets.
    Buttons: Add User | Remove Last | Import | Export
    """
    MAX_USERS = 12

    def __init__(self):
        JPanel.__init__(self, BorderLayout(0, 0))
        self.setBackground(P.BG_DARK)

        self._user_panels = []   # list of UserHeaderPanel

        # ── Toolbar ───────────────────────────────────────────
        tb = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        tb.setBackground(P.BG_DARK)
        tb.add(lbl("Users", bold=True, size=13, color=P.ACCENT))

        b_add  = mk_btn("+ Add User",      P.BTN_ADD)
        b_del  = mk_btn("- Remove Last",   P.BTN_DEL)
        b_imp  = mk_btn("Import JSON",     P.BTN_IMP)
        b_exp  = mk_btn("Export JSON",     P.BTN_EXP)

        cmp_items = ["All vs Baseline", "All vs All (matrix)"]
        tb.add(lbl("  Mode:", size=11, color=P.DIM))
        self._cmp_combo = mk_combo(cmp_items)
        self._cmp_combo.setToolTipText(
            "All vs Baseline: each user tested against the Baseline user.\n"
            "All vs All: every pair of users compared.")

        class _Add(ActionListener):
            def actionPerformed(_s, e): self._add_user()
        class _Del(ActionListener):
            def actionPerformed(_s, e): self._remove_last()
        class _Imp(ActionListener):
            def actionPerformed(_s, e): self._import_profiles()
        class _Exp(ActionListener):
            def actionPerformed(_s, e): self._export_profiles()

        b_add.addActionListener(_Add())
        b_del.addActionListener(_Del())
        b_imp.addActionListener(_Imp())
        b_exp.addActionListener(_Exp())

        for w in [b_add, b_del, b_imp, b_exp, self._cmp_combo]:
            tb.add(w)

        self.add(tb, BorderLayout.NORTH)

        # ── Scrollable user card area ─────────────────────────
        self._cards_panel = JPanel()
        self._cards_panel.setBackground(P.BG_DARK)
        self._cards_panel.setLayout(BoxLayout(self._cards_panel, BoxLayout.X_AXIS))

        self._scroll = JScrollPane(self._cards_panel)
        self._scroll.setHorizontalScrollBarPolicy(
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        self._scroll.setVerticalScrollBarPolicy(
            ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER)
        self._scroll.getViewport().setBackground(P.BG_DARK)
        self._scroll.setBorder(None)
        self.add(self._scroll, BorderLayout.CENTER)

        # Add two default users
        self._add_user(label="User A (Baseline)", is_baseline=True)
        self._add_user(label="User B")

    # internal ref trick for inner classes in Jython
    _add_user    = None
    _remove_last = None

    def _add_user(self, label=None, headers=None, is_baseline=False):
        if len(self._user_panels) >= self.MAX_USERS:
            JOptionPane.showMessageDialog(
                self, "Maximum {} users reached.".format(self.MAX_USERS),
                "Limit", JOptionPane.WARNING_MESSAGE)
            return
        idx   = len(self._user_panels)
        color = P.user_color(idx)
        if label is None:
            label = "User {}".format(chr(65 + idx))  # A, B, C …
        if headers is None:
            headers = [["Authorization", ""]]
        profile = UserProfile(label=label, headers=headers, is_baseline=is_baseline)

        ext = self
        def _baseline_cb(panel):
            ext._set_baseline(panel)

        panel = UserHeaderPanel(profile, color, on_baseline_cb=_baseline_cb)
        panel.setPreferredSize(Dimension(460, 165))
        panel.setMinimumSize(Dimension(460, 165))
        panel.setMaximumSize(Dimension(460, 165))

        self._user_panels.append(panel)
        self._cards_panel.add(panel)
        self._cards_panel.revalidate()
        self._cards_panel.repaint()

    def _remove_last(self):
        if len(self._user_panels) <= 1:
            JOptionPane.showMessageDialog(
                self, "Need at least one user.", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        panel = self._user_panels.pop()
        self._cards_panel.remove(panel)
        self._cards_panel.revalidate()
        self._cards_panel.repaint()

    def _set_baseline(self, target_panel):
        """Ensure only one panel is marked as baseline."""
        for p in self._user_panels:
            p.set_baseline(p is target_panel)

    def _export_profiles(self):
        chooser = JFileChooser()
        chooser.setDialogTitle("Export User Profiles")
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".json"):
            path += ".json"
        try:
            profiles = [p.get_profile().to_dict() for p in self._user_panels]
            data = json.dumps(profiles, indent=2)
            w = FileWriter(path)
            w.write(data)
            w.close()
            JOptionPane.showMessageDialog(
                self, "Exported to:\n" + path, "Done",
                JOptionPane.INFORMATION_MESSAGE)
        except Exception as ex:
            JOptionPane.showMessageDialog(
                self, "Export failed:\n" + str(ex), "Error",
                JOptionPane.ERROR_MESSAGE)

    def _import_profiles(self):
        chooser = JFileChooser()
        chooser.setDialogTitle("Import User Profiles (JSON)")
        if chooser.showOpenDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            br   = BufferedReader(FileReader(path))
            lines = []
            line = br.readLine()
            while line is not None:
                lines.append(line)
                line = br.readLine()
            br.close()
            raw      = "\n".join(lines)
            profiles = json.loads(raw)
            # Clear existing
            for p in list(self._user_panels):
                self._cards_panel.remove(p)
            self._user_panels = []
            for d in profiles:
                prof = UserProfile.from_dict(d)
                self._add_user(
                    label       = prof.label,
                    headers     = prof.headers,
                    is_baseline = prof.is_baseline,
                )
            self._cards_panel.revalidate()
            self._cards_panel.repaint()
            JOptionPane.showMessageDialog(
                self, "Imported {} user(s).".format(len(profiles)),
                "Done", JOptionPane.INFORMATION_MESSAGE)
        except Exception as ex:
            JOptionPane.showMessageDialog(
                self, "Import failed:\n" + str(ex), "Error",
                JOptionPane.ERROR_MESSAGE)

    def get_profiles(self):
        """Return list of UserProfile from all panels (current state)."""
        return [p.get_profile() for p in self._user_panels]

    def get_comparison_mode(self):
        return str(self._cmp_combo.getSelectedItem())


# Fix Jython self reference in methods defined with `def` inside class body
# We need to patch _add_user etc. after class is created:
_orig_add  = UserManagerPanel._add_user
_orig_del  = UserManagerPanel._remove_last
UserManagerPanel._add_user    = _orig_add
UserManagerPanel._remove_last = _orig_del


# ─────────────────────────────────────────────────────────────
#  Dynamic result table
#  Columns: #, Method, URL, Risk, Pattern, [Ux Status, Ux Len …], Result
# ─────────────────────────────────────────────────────────────
BASE_COLS    = ["#", "Method", "URL", "Risk", "Pattern"]
RESULT_COL_NAME = "Result"

COL_RISK    = 3
COL_PATTERN = 4


def build_cols(user_labels):
    """Build column list for given user label list."""
    cols = list(BASE_COLS)
    for label in user_labels:
        short = label[:8]
        cols.append("St.{}".format(short))
        cols.append("Len.{}".format(short))
    cols.append(RESULT_COL_NAME)
    return cols


class ResultsModel(DefaultTableModel):
    def __init__(self, cols):
        self._cols = cols
        DefaultTableModel.__init__(self, cols, 0)

    def isCellEditable(self, r, c):
        return False

    def getColumnClass(self, c):
        return type("")

    def col_result(self):
        return len(self._cols) - 1


class ResultRenderer(DefaultTableCellRenderer):
    def __init__(self, result_col_fn):
        DefaultTableCellRenderer.__init__(self)
        self._result_col_fn = result_col_fn

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

        elif col == self._result_col_fn():
            if "SAME" in s:
                c.setForeground(P.RED)
                c.setFont(Font("Segoe UI", Font.BOLD, 12))
            elif "Different" in s:
                c.setForeground(P.GREEN)
            elif "FILTERED" in s:
                c.setForeground(P.DIM)
            elif "ERROR" in s:
                c.setForeground(P.ORANGE)
            elif "MIXED" in s:
                c.setForeground(P.YELLOW)

        return c


# ─────────────────────────────────────────────────────────────
#  Analysis thread  —  multi-user aware
# ─────────────────────────────────────────────────────────────
class AnalysisThread(threading.Thread):

    def __init__(self, ext, messages, profiles, cmp_mode,
                 ignore_pats, smart_filter_on,
                 model, msg_store, progress_bar, log_fn, on_done_fn):
        threading.Thread.__init__(self)
        self.daemon         = True
        self._ext           = ext
        self._msgs          = messages
        self._profiles      = profiles      # list of UserProfile
        self._cmp_mode      = cmp_mode      # "All vs Baseline" | "All vs All (matrix)"
        self._pats          = ignore_pats
        self._sf            = smart_filter_on
        self._model         = model
        self._store         = msg_store
        self._pb            = progress_bar
        self._log           = log_fn
        self._on_done       = on_done_fn
        self._counter       = [model.getRowCount() + 1]

    # ── response helpers ──────────────────────────────────────
    def _get_body_str(self, resp_bytes):
        if not resp_bytes:
            return ""
        info = self._ext.helpers.analyzeResponse(resp_bytes)
        return self._ext.helpers.bytesToString(resp_bytes[info.getBodyOffset():])

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

    def _inject(self, req_bytes, svc, header_pairs):
        """
        Inject all header_pairs into the request.
        Each pair is [name, value].
        Cookies in header_pairs should be listed as ["Cookie", "k=v; k2=v2"].
        If a header already exists, replace its value.
        If not, append it.
        """
        helpers = self._ext.helpers
        info    = helpers.analyzeRequest(svc, req_bytes)
        headers = list(info.getHeaders())
        body    = req_bytes[info.getBodyOffset():]

        for hdr_name, hdr_value in header_pairs:
            name_lo  = hdr_name.lower()
            new_hdrs = []
            replaced = False

            if name_lo == "cookie":
                # Merge cookies with existing Cookie header
                for h in headers:
                    if h.lower().startswith("cookie:"):
                        existing_pairs = [x.strip() for x in h[7:].strip().split(";")]
                        # Build dict of existing cookies, then overlay new ones
                        ck_dict = {}
                        for part in existing_pairs:
                            if "=" in part:
                                k, _, v = part.partition("=")
                                ck_dict[k.strip()] = v.strip()
                        # New cookies override existing
                        for part in hdr_value.split(";"):
                            part = part.strip()
                            if "=" in part:
                                k, _, v = part.partition("=")
                                ck_dict[k.strip()] = v.strip()
                        merged = "; ".join("{}={}".format(k, v)
                                           for k, v in ck_dict.items())
                        new_hdrs.append("Cookie: " + merged)
                        replaced = True
                    else:
                        new_hdrs.append(h)
                if not replaced:
                    new_hdrs.append("Cookie: " + hdr_value)
                headers = new_hdrs

            else:
                for h in headers:
                    if h.lower().startswith(name_lo + ":"):
                        new_hdrs.append("{}: {}".format(hdr_name, hdr_value))
                        replaced = True
                    else:
                        new_hdrs.append(h)
                if not replaced:
                    new_hdrs.append("{}: {}".format(hdr_name, hdr_value))
                headers = new_hdrs

        return helpers.buildHttpMessage(headers, body)

    def _send(self, svc, req_bytes):
        try:
            return self._ext.callbacks.makeHttpRequest(svc, req_bytes)
        except Exception as e:
            self._log("[!] Network error: {}".format(e))
            return None

    def _add_row(self, row_data):
        self._model.addRow(row_data)

    def _set_progress(self, val, text):
        self._pb.setValue(val)
        self._pb.setString(text)

    # ── pair generator ────────────────────────────────────────
    def _get_pairs(self):
        """
        Returns list of (profile_a, profile_b) to compare.
        In "All vs Baseline": baseline vs each non-baseline.
        In "All vs All": every combination i < j.
        """
        profiles = self._profiles
        pairs    = []
        if "Baseline" in self._cmp_mode:
            baseline = next((p for p in profiles if p.is_baseline), None)
            if baseline is None and profiles:
                baseline = profiles[0]
            for p in profiles:
                if p is not baseline:
                    pairs.append((baseline, p))
        else:
            for i in range(len(profiles)):
                for j in range(i + 1, len(profiles)):
                    pairs.append((profiles[i], profiles[j]))
        return pairs

    # ── main loop ─────────────────────────────────────────────
    def run(self):
        total     = len(self._msgs)
        tested    = 0
        skip_c    = 0
        profiles  = self._profiles
        n_users   = len(profiles)

        self._log("[*] Received {} request(s) | {} user(s) | mode: {}".format(
            total, n_users, self._cmp_mode))

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

                # ── Send request for each user ─────────────
                user_reqs   = []
                user_resps  = []
                user_status = []
                user_len    = []
                user_hash   = []
                user_body   = []

                for prof in profiles:
                    req  = self._inject(req_bytes, svc, prof.headers)
                    resp = self._send(svc, req)
                    rb   = resp.getResponse() if resp else None
                    bs   = self._get_body_str(rb)
                    user_reqs.append(req)
                    user_resps.append(rb)
                    user_status.append(self._status(rb))
                    user_len.append(self._body_len(rb))
                    user_hash.append(self._body_hash(bs))
                    user_body.append(bs)

                # ── Compare pairs ─────────────────────────
                pairs      = self._get_pairs()
                same_pairs = []
                diff_pairs = []
                for pa, pb in pairs:
                    ia = profiles.index(pa)
                    ib = profiles.index(pb)
                    same = (user_status[ia] == user_status[ib] and
                            user_hash[ia]   == user_hash[ib])
                    label = "{} vs {}".format(pa.label, pb.label)
                    if same:
                        same_pairs.append(label)
                    else:
                        diff_pairs.append(label)

                if same_pairs and not diff_pairs:
                    result = "SAME — Possible BAC/IDOR [{}]".format(
                        ", ".join(same_pairs))
                    self._log("  [!!] SAME  [{}]  {}".format(risk, url))
                elif same_pairs and diff_pairs:
                    result = "MIXED — SAME: {} | Different: {}".format(
                        ", ".join(same_pairs), ", ".join(diff_pairs))
                    self._log("  [?] MIXED  [{}]  {}".format(risk, url))
                else:
                    result = "Different (OK)"
                    self._log("  [+] Different")

                row_num = self._counter[0]
                self._counter[0] += 1
                tested  += 1

                # Build store entry with all user req/resp
                store_entry = {"svc": svc, "users": []}
                for i, prof in enumerate(profiles):
                    store_entry["users"].append({
                        "label": prof.label,
                        "req":   user_reqs[i],
                        "resp":  user_resps[i],
                    })
                self._store[row_num] = store_entry

                # ── Build row ─────────────────────────────
                row = [row_num, method, url, risk, pattern]
                for i in range(n_users):
                    row.append(user_status[i])
                    row.append(user_len[i])
                row.append(result)

                SwingUtilities.invokeLater(lambda r=row: self._add_row(r))

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
        SwingUtilities.invokeLater(lambda: self._set_progress(0, summary))
        self._log("[*] " + summary)
        if self._on_done:
            SwingUtilities.invokeLater(self._on_done)


# ─────────────────────────────────────────────────────────────
#  Message editor controller
# ─────────────────────────────────────────────────────────────
class StaticMessageController(IMessageEditorController):
    def __init__(self):
        self._svc  = None
        self._req  = None
        self._resp = None

    def set_data(self, svc, req_bytes, resp_bytes):
        self._svc  = svc
        self._req  = req_bytes
        self._resp = resp_bytes

    def getHttpService(self):  return self._svc
    def getRequest(self):      return self._req
    def getResponse(self):     return self._resp


# ─────────────────────────────────────────────────────────────
#  Multi-user POC Panel
#  Dynamically creates one column per user (Request | Response)
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
        hdr.add(lbl("  (click a row above to load Request/Response per user)",
                    size=11, color=P.DIM))
        self.add(hdr, BorderLayout.NORTH)

        self._split_center = JPanel(BorderLayout())
        self._split_center.setBackground(P.BG_DARK)
        self.add(self._split_center, BorderLayout.CENTER)

        # Current editors
        self._editors = []   # list of dicts with ctrl_req, ctrl_resp, ed_req, ed_resp

    def _build_columns(self, user_labels):
        """Rebuild editor columns for given user label list."""
        self._split_center.removeAll()
        self._editors = []

        n = len(user_labels)
        if n == 0:
            return

        # Build each column
        cols_panel = JPanel(GridLayout(1, n, 4, 0))
        cols_panel.setBackground(P.BG_DARK)

        for i, label in enumerate(user_labels):
            color    = P.user_color(i)
            ctrl_req  = StaticMessageController()
            ctrl_resp = StaticMessageController()
            ed_req    = self._callbacks.createMessageEditor(ctrl_req,  False)
            ed_resp   = self._callbacks.createMessageEditor(ctrl_resp, False)
            self._editors.append({
                "ctrl_req": ctrl_req, "ctrl_resp": ctrl_resp,
                "ed_req":   ed_req,   "ed_resp":   ed_resp,
            })

            col   = JPanel(BorderLayout())
            col.setBackground(P.BG_DARK)
            title = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
            title.setBackground(P.BG_PANEL)
            title.add(lbl(label, bold=True, size=11, color=color))
            col.add(title, BorderLayout.NORTH)

            req_p  = self._wrap("Request",  ed_req.getComponent(),  color)
            resp_p = self._wrap("Response", ed_resp.getComponent(), color)

            vsplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, req_p, resp_p)
            vsplit.setResizeWeight(0.5)
            vsplit.setBackground(P.BG_DARK)
            vsplit.setBorder(None)
            vsplit.setDividerSize(4)
            col.add(vsplit, BorderLayout.CENTER)
            cols_panel.add(col)

        sc = JScrollPane(cols_panel)
        sc.getViewport().setBackground(P.BG_DARK)
        sc.setBorder(None)
        sc.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        self._split_center.add(sc, BorderLayout.CENTER)
        self._split_center.revalidate()
        self._split_center.repaint()

    def _wrap(self, title, component, color):
        p = JPanel(BorderLayout())
        p.setBackground(P.BG_DARK)
        hdr = JPanel(FlowLayout(FlowLayout.LEFT, 4, 1))
        hdr.setBackground(P.BG_PANEL)
        hdr.add(lbl(title, bold=True, size=10, color=color))
        p.add(hdr, BorderLayout.NORTH)
        p.add(component, BorderLayout.CENTER)
        p.setBorder(BorderFactory.createLineBorder(P.BORDER, 1))
        return p

    def show_poc(self, svc, user_data_list):
        """
        user_data_list: list of dicts {"label", "req", "resp"}
        """
        labels = [u["label"] for u in user_data_list]
        # Rebuild columns if user count changed
        if len(user_data_list) != len(self._editors):
            self._build_columns(labels)

        empty = jarray.array([], "b")
        for i, ud in enumerate(user_data_list):
            ed   = self._editors[i]
            req  = ud.get("req")
            resp = ud.get("resp")
            ed["ctrl_req"].set_data(svc,  req,  None)
            ed["ctrl_resp"].set_data(svc, req,  resp)
            ed["ed_req"].setMessage(req   if req  else empty, True)
            ed["ed_resp"].setMessage(resp if resp else empty, False)

    def clear(self):
        empty = jarray.array([], "b")
        for ed in self._editors:
            ed["ed_req"].setMessage(empty,  True)
            ed["ed_resp"].setMessage(empty, False)


# ─────────────────────────────────────────────────────────────
#  Main extension
# ─────────────────────────────────────────────────────────────
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("TokenTwin Checker")

        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._log("TokenTwin Checker v4.0 loaded  (Multi-User + Header Manager)")

        self._msg_store = {}
        self._ui_ready  = threading.Event()
        SwingUtilities.invokeLater(self._build_ui)
        self._ui_ready.wait(5)

        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    # ── ITab ─────────────────────────────────────────────────
    def getTabCaption(self):  return "TokenTwin"
    def getUiComponent(self): return self._root

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

        top_split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            self._make_config_panel(),
            self._make_center_split()
        )
        top_split.setDividerLocation(215)
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
        p.add(lbl("v4.0  |  Multi-User BAC / IDOR Hunter", size=12, color=P.DIM))
        return p

    # ── Config panel ──────────────────────────────────────────
    def _make_config_panel(self):
        """
        Top section split into:
          LEFT  — UserManagerPanel (user cards)
          RIGHT — options (ignore regex, smart filter, progress, buttons)
        """
        outer = JPanel(BorderLayout())
        outer.setBackground(P.BG_DARK)
        outer.setBorder(EmptyBorder(6, 10, 4, 10))

        # Left: user manager
        self._user_mgr = UserManagerPanel()
        self._user_mgr.setPreferredSize(Dimension(0, 190))

        # Right: options pane
        opt = JPanel(GridBagLayout())
        opt.setBackground(P.BG_PANEL)
        opt.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(P.BORDER, 1),
            EmptyBorder(8, 10, 8, 10)
        ))
        opt.setPreferredSize(Dimension(340, 190))
        opt.setMinimumSize(Dimension(300, 170))

        g = GridBagConstraints()
        g.insets  = Insets(3, 4, 3, 4)
        g.fill    = GridBagConstraints.HORIZONTAL
        g.anchor  = GridBagConstraints.WEST

        # Ignore regex
        g.gridx, g.gridy, g.gridwidth = 0, 0, 1
        opt.add(lbl("Ignore regex:", bold=True, size=11), g)
        g.gridx = 1; g.gridwidth = 3
        self._ignore_field = fld(30, '"nonce":"[^"]*"|"timestamp":\\d+')
        self._ignore_field.setToolTipText(
            "Pipe-separated regex patterns stripped from body before hash comparison")
        opt.add(self._ignore_field, g)

        # Smart filter
        g.gridx, g.gridy, g.gridwidth = 0, 1, 4
        self._sf_cb = mk_cb("Smart Filter (skip static/irrelevant endpoints)")
        self._sf_cb.setSelected(True)
        opt.add(self._sf_cb, g)

        # Progress bar
        g.gridx, g.gridy, g.gridwidth = 0, 2, 4
        self._pb = JProgressBar(0, 100)
        self._pb.setStringPainted(True)
        self._pb.setString("Ready")
        self._pb.setBackground(P.BG_FIELD)
        self._pb.setForeground(P.ACCENT)
        self._pb.setBorder(BorderFactory.createLineBorder(P.BORDER, 1))
        self._pb.setPreferredSize(Dimension(0, 18))
        opt.add(self._pb, g)

        # Buttons
        b_run  = mk_btn("▶ Run Test",   P.ACCENT)
        b_clr  = mk_btn("Clear All",    P.BTN_CLR)
        b_exp  = mk_btn("Export CSV",   P.BTN_EXP)

        class _Run(ActionListener):
            def actionPerformed(_s, e): self._run_from_stored()
        class _Clr(ActionListener):
            def actionPerformed(_s, e):
                self._model.setRowCount(0)
                self._msg_store.clear()
                self._poc_panel.clear()
                self._last_profile_labels = None
                self._log("[*] Results cleared.")
        class _Exp(ActionListener):
            def actionPerformed(_s, e): self._export_csv()

        b_run.addActionListener(_Run())
        b_clr.addActionListener(_Clr())
        b_exp.addActionListener(_Exp())
        b_run.setToolTipText("Re-run test on last received requests with current user config")

        g.gridx, g.gridy, g.gridwidth = 0, 3, 4
        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        btn_row.setBackground(P.BG_PANEL)
        for b in [b_run, b_clr, b_exp]:
            btn_row.add(b)
        opt.add(btn_row, g)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._user_mgr, opt)
        split.setDividerLocation(700)
        split.setResizeWeight(0.75)
        split.setBackground(P.BG_DARK)
        split.setBorder(None)
        split.setDividerSize(5)

        outer.add(split, BorderLayout.CENTER)
        return outer

    # ── Center: table | poc | log ─────────────────────────────
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

        hdr = JPanel(FlowLayout(FlowLayout.LEFT, 8, 3))
        hdr.setBackground(P.BG_DARK)
        hdr.add(lbl("Results", bold=True, size=13, color=P.ACCENT))
        hdr.add(lbl("  Filter:", size=11, color=P.DIM))

        self._filter_all  = self._filter_btn("All")
        self._filter_same = self._filter_btn("SAME only")
        self._filter_high = self._filter_btn("HIGH risk only")
        self._filter_mix  = self._filter_btn("MIXED only")

        class _FA(ActionListener):
            def actionPerformed(_s, e): self._apply_filter("all")
        class _FS(ActionListener):
            def actionPerformed(_s, e): self._apply_filter("same")
        class _FH(ActionListener):
            def actionPerformed(_s, e): self._apply_filter("high")
        class _FM(ActionListener):
            def actionPerformed(_s, e): self._apply_filter("mixed")

        self._filter_all.addActionListener(_FA())
        self._filter_same.addActionListener(_FS())
        self._filter_high.addActionListener(_FH())
        self._filter_mix.addActionListener(_FM())
        self._active_filter = "all"

        for b in [self._filter_all, self._filter_same,
                  self._filter_high, self._filter_mix]:
            hdr.add(b)
        p.add(hdr, BorderLayout.NORTH)

        # Build with dummy 2-user columns initially; rebuilt on each run
        init_cols  = build_cols(["User A", "User B"])
        self._model = ResultsModel(init_cols)
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

        rr = ResultRenderer(lambda: self._model.col_result())
        cm = self._table.getColumnModel()
        for i in range(len(init_cols)):
            cm.getColumn(i).setCellRenderer(rr)

        ext_ref = self

        class _Sel(ListSelectionListener):
            def valueChanged(_self, e):
                if e.getValueIsAdjusting():
                    return
                view_row = ext_ref._table.getSelectedRow()
                if view_row < 0:
                    return
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
                    ext_ref._poc_panel.show_poc(data["svc"], data["users"])

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
        for b, m in [(self._filter_all,  "all"),
                     (self._filter_same, "same"),
                     (self._filter_high, "high"),
                     (self._filter_mix,  "mixed")]:
            if m == mode:
                b.setBackground(P.ACCENT)
                b.setForeground(Color(0x1E, 0x1E, 0x2E))
            else:
                b.setBackground(P.BG_FIELD)
                b.setForeground(P.TEXT)

        import javax.swing.table as jst
        sorter = jst.TableRowSorter(self._model)
        self._table.setRowSorter(sorter)
        rc = self._model.col_result()

        if mode == "all":
            sorter.setRowFilter(None)
        elif mode == "same":
            class _F(jst.RowFilter):
                def include(_self, entry):
                    v = str(entry.getValue(rc) or "")
                    return "SAME" in v
            sorter.setRowFilter(_F())
        elif mode == "high":
            class _F2(jst.RowFilter):
                def include(_self, entry):
                    risk   = str(entry.getValue(COL_RISK) or "")
                    result = str(entry.getValue(rc) or "")
                    return risk == "HIGH" and "SAME" in result
            sorter.setRowFilter(_F2())
        elif mode == "mixed":
            class _F3(jst.RowFilter):
                def include(_self, entry):
                    v = str(entry.getValue(rc) or "")
                    return "MIXED" in v
            sorter.setRowFilter(_F3())

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
    def _get_ignore_pats(self):
        raw = self._ignore_field.getText().strip()
        return [x.strip() for x in raw.split("|") if x.strip()] if raw else []

    def _rebuild_model(self, profiles):
        """Rebuild result table columns for the given user list."""
        labels    = [p.label for p in profiles]
        new_cols  = build_cols(labels)
        new_model = ResultsModel(new_cols)

        self._model = new_model
        self._table.setModel(new_model)

        # Re-apply renderer
        rr = ResultRenderer(lambda: self._model.col_result())
        cm = self._table.getColumnModel()
        for i in range(len(new_cols)):
            cm.getColumn(i).setCellRenderer(rr)

        # Auto column widths
        base_widths = [30, 58, 280, 55, 160]
        for _ in labels:
            base_widths.extend([52, 60])
        base_widths.append(220)
        for i, w in enumerate(base_widths[:len(new_cols)]):
            cm.getColumn(i).setPreferredWidth(w)

    def _enqueue(self, messages):
        profiles = self._user_mgr.get_profiles()
        if not profiles:
            JOptionPane.showMessageDialog(
                self._root, "Add at least one user.",
                "No Users", JOptionPane.WARNING_MESSAGE)
            return

        # Validate: every user must have at least one non-empty header
        for prof in profiles:
            pairs = prof.headers
            has_value = any(v.strip() for _, v in pairs)
            if not has_value:
                JOptionPane.showMessageDialog(
                    self._root,
                    "User '{}' has no header values set.\n"
                    "Please fill in at least one header value.".format(prof.label),
                    "Missing Header Value", JOptionPane.WARNING_MESSAGE)
                return

        cmp_mode = self._user_mgr.get_comparison_mode()

        # If "All vs Baseline" but no baseline set, warn
        if "Baseline" in cmp_mode:
            if not any(p.is_baseline for p in profiles):
                JOptionPane.showMessageDialog(
                    self._root,
                    "No user is marked as Baseline.\n"
                    "The first user will be used as Baseline.",
                    "Baseline Not Set", JOptionPane.WARNING_MESSAGE)
                profiles[0].is_baseline = True

        # Prevent overlapping runs — wait for previous thread to finish
        active = getattr(self, "_active_thread", None)
        if active is not None and active.is_alive():
            JOptionPane.showMessageDialog(
                self._root,
                "A test is still running.\nWait for it to finish or Clear results first.",
                "Busy", JOptionPane.WARNING_MESSAGE)
            return

        # Rebuild columns only if user structure changed (label set differs)
        new_labels = [p.label for p in profiles]
        cur_labels = getattr(self, "_last_profile_labels", None)
        if cur_labels != new_labels:
            self._rebuild_model(profiles)
            self._last_profile_labels = new_labels

        # Do NOT clear msg_store or results — append new results to existing list
        # Store messages for possible re-run
        self._last_messages = messages

        ext_self = self

        def _after_done():
            ext_self._apply_filter(ext_self._active_filter)

        t = AnalysisThread(
            ext             = self,
            messages        = messages,
            profiles        = profiles,
            cmp_mode        = cmp_mode,
            ignore_pats     = self._get_ignore_pats(),
            smart_filter_on = self._sf_cb.isSelected(),
            model           = self._model,
            msg_store       = self._msg_store,
            progress_bar    = self._pb,
            log_fn          = self._log,
            on_done_fn      = _after_done,
        )
        self._active_thread = t
        self._pb.setValue(0)
        self._pb.setString("Starting…")
        t.start()

    def _run_from_stored(self):
        """Re-run the last batch of requests with current user config."""
        msgs = getattr(self, "_last_messages", None)
        if not msgs:
            JOptionPane.showMessageDialog(
                self._root,
                "No requests loaded yet.\n"
                "Right-click a request in Burp and choose\n"
                "\"Send to TokenTwin Checker\".",
                "No Requests", JOptionPane.INFORMATION_MESSAGE)
            return
        self._enqueue(msgs)

    def _export_csv(self):
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Results as CSV")
        if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".csv"):
            path += ".csv"
        try:
            cols = [str(self._model.getColumnName(c))
                    for c in range(self._model.getColumnCount())]
            w = FileWriter(path)
            w.write(",".join(cols) + "\n")
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


import javax.swing
