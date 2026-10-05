"""Rethink Root — native GTK4/libadwaita desktop app for the rethinkd daemon.

Layout mirrors the Android app: a Home dashboard with a protection bar, cards
and a start/stop cluster, plus Firewall, DNS (blocklists + domain rules),
Logs, Stats, Proxy and Settings pages — all driven by the local HTTP API.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango  # noqa: E402

if "rethinkd" not in sys.modules:
    for candidate in (Path(__file__).resolve().parents[1], Path("/usr/lib/rethinkd")):
        if (candidate / "rethinkd").is_dir():
            sys.path.insert(0, str(candidate))
            break

try:
    from rethinkd.client import ApiError, call, ui_url
except ImportError:  # pragma: no cover - exercised only on broken installs
    ApiError = RuntimeError  # type: ignore[assignment]
    call = None  # type: ignore[assignment]

    def ui_url() -> str:  # type: ignore[misc]
        return ""


APP_ID = "rs.rethinkroot.App"
POLL_SECONDS = 3
ICONS = {
    "home": "user-home-symbolic",
    "firewall": "security-high-symbolic",
    "dns": "network-server-symbolic",
    "logs": "view-list-symbolic",
    "stats": "utilities-system-monitor-symbolic",
    "proxy": "network-transmit-receive-symbolic",
    "settings": "preferences-system-symbolic",
}
PAGE_ORDER = ("home", "firewall", "dns", "logs", "stats", "proxy", "settings")

CSS = """
.rt-card { padding: 15px 17px 17px 17px; border-radius: 16px;
           background-color: alpha(@view_fg_color, 0.055);
           border: 1px solid alpha(@view_fg_color, 0.11); }
.rt-card.tight { padding: 11px 14px 13px 14px; min-height: 64px; }
.rt-head { font-weight: 700; font-size: 10pt; letter-spacing: 1.1px;
           opacity: 0.72; }
.rt-title { font-weight: 600; font-size: 11pt; }
.rt-num { font-size: 27px; font-weight: 800; letter-spacing: -0.6px;
          margin-top: 2px; }
.rt-num.small { font-size: 18px; }
.rt-sub { opacity: 0.62; font-size: 9.5pt; }
.rt-muted { opacity: 0.6; }
.ok { color: @success_color; }
.bad { color: @error_color; }
.rt-bar { padding: 14px 18px; border-radius: 14px; font-size: 12.5pt;
          font-weight: 800; letter-spacing: 2.4px; }
.rt-bar.ok { background-color: alpha(@success_color, 0.16);
             color: @success_color;
             border: 1px solid alpha(@success_color, 0.42); }
.rt-bar.off { background-color: alpha(@error_color, 0.14);
              color: @error_color;
              border: 1px solid alpha(@error_color, 0.40); }
.rt-pill { padding: 3px 10px; border-radius: 999px; font-size: 8.5pt;
           font-weight: 700; letter-spacing: 0.3px; }
.rt-pill.ok { background-color: alpha(@success_color, 0.18); color: @success_color; }
.rt-pill.bad { background-color: alpha(@error_color, 0.18); color: @error_color; }
.rt-pill.warn { background-color: alpha(@warning_color, 0.18); color: @warning_color; }
.rt-pill.dim { background-color: alpha(@view_fg_color, 0.10); opacity: 0.85; }
.rt-pill.accent { background-color: alpha(@accent_color, 0.20); color: @accent_color; }
.rt-row { padding: 9px 4px; border-radius: 9px; }
.rt-row:hover { background-color: alpha(@view_fg_color, 0.05); }
.rt-sep { margin: 0; opacity: 0.45; }
.rt-nav row { padding: 9px 8px; min-height: 38px; border-radius: 11px;
              margin: 1px 6px; }
.rt-nav row:hover { background-color: alpha(@view_fg_color, 0.07); }
.rt-nav row:selected { background-color: alpha(@accent_color, 0.22); }
.rt-nav row:selected .rt-nav-label { font-weight: 700; color: @accent_color; }
.rt-nav-label { font-size: 11.5pt; }
.rt-nav-count { font-size: 8.5pt; opacity: 0.65; letter-spacing: 0.2px; }
.rt-bigbtn { font-size: 14pt; font-weight: 800; letter-spacing: 3px;
             padding: 15px 26px; border-radius: 15px; }
.rt-section { font-size: 9.5pt; font-weight: 700; opacity: 0.62;
              letter-spacing: 1px; margin-top: 8px; }
.rt-dock { padding: 12px 16px;
           border-top: 1px solid alpha(@view_fg_color, 0.12);
           background-color: alpha(@view_bg_color, 0.92); }
.rt-link { font-weight: 700; color: @accent_color; }
.rt-chart-rest { background-color: alpha(@view_fg_color, 0.20);
                 border-radius: 3px; min-width: 4px; }
.rt-chart-blocked { background-color: #e64553; border-radius: 3px; min-width: 4px; }
.rt-brand { font-weight: 800; letter-spacing: 1.4px; }
"""


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def esc(value) -> str:
    return GLib.markup_escape_text(str(value))


def fmt_num(value) -> str:
    try:
        n = float(value or 0)
    except (TypeError, ValueError):
        return "0"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 10_000:
        return f"{n / 1_000:.1f}k"
    if n >= 1000:
        return f"{n:,.0f}".replace(",", " ")
    return f"{int(n)}"


def fmt_duration(seconds) -> str:
    try:
        s = int(seconds or 0)
    except (TypeError, ValueError):
        return "0s"
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    mins, s = divmod(s, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {mins}m"
    if mins:
        return f"{mins}m {s}s"
    return f"{s}s"


def fmt_time(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "--:--:--"


def label(text, css=("",), xalign=0, wrap=False) -> Gtk.Label:
    widget = Gtk.Label(label=str(text), xalign=xalign, selectable=False)
    for cls in css:
        if cls:
            widget.add_css_class(cls)
    if "rt-pill" in css:
        widget.set_halign(Gtk.Align.START)
        widget.set_valign(Gtk.Align.CENTER)
    if wrap:
        widget.set_wrap(True)
        widget.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    return widget


def api(method, path, payload=None, ok=None, err=None, timeout=60.0) -> None:
    """Fire an API call on a worker thread; marshal callbacks to the UI loop."""

    def work() -> None:
        try:
            data = call(method, path, payload, timeout=timeout)
        except ApiError as exc:  # type: ignore[misc]
            if err is not None:
                GLib.idle_add(err, str(exc))
            return
        if ok is not None:
            GLib.idle_add(ok, data)
        GLib.idle_add(lambda: False)

    threading.Thread(target=work, daemon=True).start()


def chip(text, css="dim") -> Gtk.Label:
    widget = Gtk.Label(label=str(text))
    widget.add_css_class("rt-pill")
    widget.add_css_class(css)
    widget.set_halign(Gtk.Align.START)
    widget.set_valign(Gtk.Align.CENTER)
    return widget


def linked(*buttons: Gtk.Widget) -> Gtk.Box:
    box = Gtk.Box(spacing=0)
    box.add_css_class("linked")
    for btn in buttons:
        box.append(btn)
    return box


def toggle_chip(text: str, active=False) -> Gtk.ToggleButton:
    btn = Gtk.ToggleButton(label=text)
    btn.set_active(active)
    return btn


def card(title: str, subtitle: str | None = None, extra: Gtk.Widget | None = None,
         tight: bool = False) -> tuple[Gtk.Box, Gtk.Box]:
    """Return (card widget, content box) — rows get appended to the content."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.add_css_class("rt-card")
    if tight:
        box.add_css_class("tight")
    if title or extra is not None:
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        if title:
            head.append(label(title, ("rt-head",)))
        head.set_valign(Gtk.Align.CENTER)
        if subtitle:
            sub = label(subtitle, ("rt-sub",))
            sub.set_valign(Gtk.Align.CENTER)
            head.append(sub)
        if extra is not None:
            extra.set_valign(Gtk.Align.CENTER)
            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            head.append(spacer)
            head.append(extra)
        box.append(head)
    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    box.append(content)
    return box, content


def row_widget(title, subtitle=None, suffix: Gtk.Widget | None = None,
               prefix: Gtk.Widget | None = None) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
    box.add_css_class("rt-row")
    if prefix is not None:
        prefix.set_valign(Gtk.Align.CENTER)
        box.append(prefix)
    texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    texts.set_hexpand(True)
    title_lbl = label(title, ("rt-title",))
    title_lbl.set_ellipsize(Pango.EllipsizeMode.END)
    texts.append(title_lbl)
    if subtitle:
        sub = label(subtitle, ("rt-sub",))
        sub.set_ellipsize(Pango.EllipsizeMode.END)
        texts.append(sub)
    box.append(texts)
    if suffix is not None:
        suffix.set_valign(Gtk.Align.CENTER)
        box.append(suffix)
    return box


def sep() -> Gtk.Separator:
    widget = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
    widget.add_css_class("rt-sep")
    return widget


def spinner() -> Gtk.Spinner:
    widget = Gtk.Spinner()
    widget.set_valign(Gtk.Align.CENTER)
    return widget


def icon_button(icon: str, tooltip: str, on_click) -> Gtk.Button:
    btn = Gtk.Button(icon_name=icon, tooltip_text=tooltip)
    btn.connect("clicked", on_click)
    return btn


def clear(container: Gtk.Box) -> None:
    while (child := container.get_first_child()) is not None:
        container.remove(child)


def add_rows(container: Gtk.Box, rows: list[Gtk.Widget]) -> None:
    clear(container)
    for i, widget in enumerate(rows):
        if i:
            container.append(sep())
        container.append(widget)


# --------------------------------------------------------------------------- #
# page base
# --------------------------------------------------------------------------- #
class Page:
    title = ""
    icon = "view-paged-symbolic"
    auto_refresh = False

    def __init__(self, win: "RethinkWindow") -> None:
        self.win = win
        self.data: dict = {}
        self.error: str | None = None
        self.widget: Gtk.Widget = self.build()

    # -- API sugar ---------------------------------------------------------
    def get(self, path, ok, err=None, timeout=30.0) -> None:
        api("GET", path, None,
            ok=lambda data: self._ok(data, ok),
            err=err or (lambda e: self._fail(e)), timeout=timeout)

    def post(self, path, payload, ok=None, err=None, timeout=60.0) -> None:
        api("POST", path, payload,
            ok=lambda data: self._ok(data, ok),
            err=err or (lambda e: self._fail(e)), timeout=timeout)

    def delete(self, path, ok=None, err=None) -> None:
        api("DELETE", path, None,
            ok=lambda data: self._ok(data, ok),
            err=err or (lambda e: self._fail(e)))

    def _ok(self, data, ok) -> None:
        self.error = None
        if ok is not None:
            ok(data)

    def _fail(self, message: str) -> None:
        self.error = message
        self.win.toast(message)

    # -- lifecycle ---------------------------------------------------------
    def build(self) -> Gtk.Widget:  # pragma: no cover - abstract
        raise NotImplementedError

    def load(self) -> None:  # pragma: no cover - optional
        pass

    def refresh(self) -> None:
        self.load()


# --------------------------------------------------------------------------- #
# home
# --------------------------------------------------------------------------- #
class HomePage(Page):
    title = "Home"
    icon = ICONS["home"]

    def build(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        root.set_margin_top(16)
        root.set_margin_bottom(8)
        root.set_margin_start(18)
        root.set_margin_end(18)

        # protection bar ---------------------------------------------------
        self.bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.bar.add_css_class("rt-bar")
        self.bar.set_valign(Gtk.Align.CENTER)
        self.bar_icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
        self.bar_icon.set_valign(Gtk.Align.CENTER)
        self.bar.append(self.bar_icon)
        self.bar_status = label("CHECKING…", ())
        self.bar_status.set_valign(Gtk.Align.CENTER)
        self.bar_info = label("", ())
        self.bar_info.set_xalign(1)
        self.bar_info.set_valign(Gtk.Align.CENTER)
        self.bar_info.set_opacity(0.85)
        self.bar_info.set_ellipsize(Pango.EllipsizeMode.END)
        self.bar.append(self.bar_status)
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        self.bar.append(spacer)
        self.bar.append(self.bar_info)
        root.append(self.bar)

        # row 1: DNS + last hour ------------------------------------------
        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        self.dns_card, dns_body = card("DNS", extra=self._pill())
        self.dns_num = label("—", ("rt-num",))
        dns_body.append(self.dns_num)
        dns_body.append(label("queries", ("rt-sub",)))
        dns_stats = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.dns_blocked = label("0 blocked", ("rt-pill", "dim"))
        self.dns_rate = label("0%", ("rt-pill", "dim"))
        dns_stats.append(self.dns_blocked)
        dns_stats.append(self.dns_rate)
        dns_body.append(dns_stats)
        self.dns_bar = Gtk.ProgressBar()
        self.dns_bar.set_valign(Gtk.Align.CENTER)
        dns_body.append(self.dns_bar)
        self.dns_up = label("upstream —", ("rt-sub",))
        self.dns_up.set_ellipsize(Pango.EllipsizeMode.END)
        dns_body.append(self.dns_up)
        self.dns_card.append(self._open("DNS settings", "dns"))
        row1.append(self.dns_card)
        self.dns_card.set_hexpand(True)

        self.hour_card, hour_body = card("LAST HOUR", extra=self._pill("60 min"))
        self.hour_num = label("—", ("rt-num",))
        hour_body.append(self.hour_num)
        hour_body.append(label("queries", ("rt-sub",)))
        self.hour_blocked = label("0 blocked", ("rt-pill", "dim"))
        hour_body.append(self.hour_blocked)
        self.hour_bar = Gtk.ProgressBar()
        hour_body.append(self.hour_bar)
        self.hour_top = label("top blocked —", ("rt-sub",))
        self.hour_top.set_ellipsize(Pango.EllipsizeMode.END)
        hour_body.append(self.hour_top)
        self.hour_card.append(self._open("Statistics", "stats"))
        row1.append(self.hour_card)
        self.hour_card.set_hexpand(True)
        root.append(row1)

        # row 2: firewall + proxy -----------------------------------------
        row2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        self.fw_card, fw_body = card("FIREWALL", extra=self._pill())
        self.fw_num = label("—", ("rt-num",))
        fw_body.append(self.fw_num)
        fw_body.append(label("apps explicitly blocked", ("rt-sub",)))
        self.fw_policy = label("policy —", ("rt-pill", "dim"))
        fw_body.append(self.fw_policy)
        self.fw_dropped = label("0 packets dropped", ("rt-sub",))
        fw_body.append(self.fw_dropped)
        self.fw_card.append(self._open("Per-app firewall", "firewall"))
        row2.append(self.fw_card)
        self.fw_card.set_hexpand(True)

        self.proxy_switch = Gtk.Switch()
        self.proxy_switch.set_valign(Gtk.Align.CENTER)
        self.proxy_switch.set_halign(Gtk.Align.END)
        self.proxy_switch.connect("notify::active", self._on_proxy_switch)
        self.proxy_sync = False
        proxy_tools = Gtk.Box(spacing=8)
        proxy_tools.append(self._pill())
        proxy_tools.append(self.proxy_switch)
        self.proxy_card, proxy_body = card("PROXY", extra=proxy_tools)
        self.proxy_num = label("inactive", ("rt-num small",))
        proxy_body.append(self.proxy_num)
        self.proxy_sub = label("HTTP / SOCKS5 exit node", ("rt-sub",))
        proxy_body.append(self.proxy_sub)
        self.proxy_stats = label("0 relayed · 0 open", ("rt-sub",))
        proxy_body.append(self.proxy_stats)
        self.proxy_err = label("", ("rt-sub",))
        self.proxy_err.set_ellipsize(Pango.EllipsizeMode.END)
        proxy_body.append(self.proxy_err)
        self.proxy_card.append(self._open("Proxy settings", "proxy"))
        row2.append(self.proxy_card)
        self.proxy_card.set_hexpand(True)
        root.append(row2)

        # row 3: apps + activity ------------------------------------------
        row3 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        self.apps_card, apps_body = card("APPS", extra=self._pill("0 seen"))
        self.apps_num = label("—", ("rt-num",))
        apps_body.append(self.apps_num)
        apps_body.append(label("apps discovered from /proc", ("rt-sub",)))
        self.apps_chips = Gtk.Box(spacing=6)
        apps_body.append(self.apps_chips)
        self.apps_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        apps_body.append(self.apps_list)
        self.apps_card.append(self._open("Manage apps", "firewall"))
        row3.append(self.apps_card)
        self.apps_card.set_hexpand(True)

        self.act_card, act_body = card("RECENT ACTIVITY", extra=self._pill("live"))
        self.act_body = act_body
        self.act_hint = label("loading…", ("rt-sub",))
        act_body.append(self.act_hint)
        self.act_card.append(self._open("Open logs", "logs"))
        row3.append(self.act_card)
        self.act_card.set_hexpand(True)
        root.append(row3)

        # dock --------------------------------------------------------------
        dock = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        dock.add_css_class("rt-dock")
        self.start_stop = Gtk.Button(label="STOP")
        self.start_stop.add_css_class("rt-bigbtn")
        self.start_stop.add_css_class("suggested-action")
        self.start_stop.connect("clicked", self._on_start_stop)
        dock.append(self.start_stop)
        self.start_stop.set_hexpand(True)
        self.pause_btn = Gtk.Button(icon_name="media-playback-pause-symbolic",
                                    tooltip_text="Pause protection for a while")
        self.pause_btn.add_css_class("pill")
        self.pause_btn.connect("clicked", self._on_pause)
        dock.append(self.pause_btn)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh (Ctrl+R)")
        refresh.add_css_class("pill")
        refresh.connect("clicked", lambda *_: self.win.refresh_all())
        dock.append(refresh)
        web = Gtk.Button(label="Web UI")
        web.add_css_class("pill")
        web.connect("clicked", lambda *_: self.win.open_web_ui())
        dock.append(web)
        self.content_scroll = self._scroll(root)
        shell = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        shell.append(self.content_scroll)
        shell.append(dock)
        return shell

    # -- builders ----------------------------------------------------------
    def _scroll(self, child: Gtk.Widget) -> Gtk.Widget:
        scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(child)
        return scroller

    def _pill(self, text="—") -> Gtk.Label:
        return chip(text, "dim")

    def _open(self, text: str, page: str, extra_widget: Gtk.Widget | None = None) -> Gtk.Box:
        box = Gtk.Box(spacing=8)
        if extra_widget is not None:
            extra_widget.set_valign(Gtk.Align.CENTER)
            box.append(extra_widget)
        btn = Gtk.Button(label=text)
        btn.add_css_class("flat")
        btn.add_css_class("rt-link")
        btn.set_halign(Gtk.Align.END)
        btn.connect("clicked", lambda *_: self.win.navigate(page))
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        box.append(spacer)
        box.append(btn)
        return box

    # -- data --------------------------------------------------------------
    def load(self) -> None:
        self.get("/api/activity?limit=8", ok=self._loaded_activity)
        self.get("/api/apps", ok=self._loaded_apps)
        self.get("/api/stats", ok=self._loaded_stats)
        self._paint_status()

    def _paint_status(self) -> None:
        st = self.win.status or {}
        dns = st.get("dns") or {}
        fw = st.get("firewall") or {}
        proxy = st.get("proxy") or {}
        protected = bool(st.get("protected"))
        self.bar.add_css_class("ok" if protected else "off")
        self.bar.remove_css_class("off" if protected else "ok")
        self.bar_status.set_text("PROTECTED · FILTERING" if protected else "STOPPED · NO FILTERING")
        info = f"active {fmt_duration(st.get('uptime_s'))}"
        if st.get("running_as"):
            info += f" · {st['running_as']}"
        if st.get("host", {}).get("os"):
            info += f" · {st['host']['os']}"
        self.bar_info.set_text(info)

        queries = dns.get("queries", 0)
        blocked = dns.get("blocked", 0)
        listening = bool(dns.get("listening"))
        self.dns_num.set_text(fmt_num(queries))
        self.dns_blocked.set_text(f"{fmt_num(blocked)} blocked")
        rate = float(dns.get("block_rate") or 0)
        self.dns_rate.set_text(f"{rate:.1f}% blocked")
        self.dns_bar.set_fraction(min(1.0, max(0.0, rate / 100.0)))
        upstream = str(dns.get("upstream") or "system")
        up_url = str(dns.get("upstream_url") or "")
        self.dns_up.set_text(f"upstream {upstream}" + (f" · {up_url}" if up_url else ""))
        self._set_pill(self.dns_card, "Connected" if listening and protected else ("Listening" if listening else "Off"),
                       "ok" if listening else "bad")

        last_hour = dns.get("last_hour") or {}
        self.hour_num.set_text(fmt_num(last_hour.get("total", 0)))
        hb = int(last_hour.get("blocked", 0))
        self.hour_blocked.set_text(f"{fmt_num(hb)} blocked")
        ht = int(last_hour.get("total", 0)) or 1
        self.hour_bar.set_fraction(min(1.0, hb / ht))

        explicit = int(fw.get("apps_blocked", 0) or 0)
        self.fw_num.set_text(str(explicit))
        self.fw_policy.set_text(f"policy {str(fw.get('policy') or 'allow')}")
        self.fw_dropped.set_text(f"{fmt_num(fw.get('dropped_packets', 0))} packets dropped")
        self._set_pill(self.fw_card, "Enforcing" if fw.get("enabled") else "Off",
                       "ok" if fw.get("enabled") else "dim")

        self._set_pill(self.proxy_card, "Active" if proxy.get("enabled") else "Inactive",
                       "accent" if proxy.get("enabled") else "dim")
        self.proxy_num.set_text(str(proxy.get("endpoint") or "inactive"))
        if not proxy.get("enabled"):
            self.proxy_num.set_text("inactive")
        self.proxy_stats.set_text(f"{fmt_num(proxy.get('relayed', 0))} relayed · "
                                  f"{fmt_num(proxy.get('active_conns', 0))} open")
        self.proxy_sync = True
        self.proxy_switch.set_active(bool(proxy.get("enabled")))
        self.proxy_sync = False

        self.start_stop.set_label("STOP" if protected else "START")
        self.start_stop.get_style_context().remove_class("suggested-action")
        self.start_stop.get_style_context().remove_class("destructive-action")
        self.start_stop.add_css_class("destructive-action" if protected else "suggested-action")

    def _set_pill(self, card_widget: Gtk.Box, text: str, css: str) -> None:
        head = card_widget.get_first_child()
        widget = None
        stack = [head]
        while stack and widget is None:
            node = stack.pop()
            child = node.get_first_child() if hasattr(node, "get_first_child") else None
            while child is not None:
                if isinstance(child, Gtk.Label) and child.has_css_class("rt-pill"):
                    widget = child
                    break
                stack.append(child)
                child = child.get_next_sibling()
        if widget is None:
            return
        widget.set_text(text)
        for cls in ("ok", "bad", "warn", "dim", "accent"):
            widget.remove_css_class(cls)
        widget.add_css_class(css)

    def _loaded_activity(self, data: dict) -> None:
        events = list(data.get("events") or [])
        clear(self.act_body)
        if not events:
            self.act_body.append(label("No activity yet", ("rt-sub",)))
            return
        for event in events[:6]:
            action = str(event.get("action") or "")
            blocked = action in ("blocked", "drop", "block")
            dot = Gtk.Label(label="●")
            dot.add_css_class("bad" if blocked else "ok")
            dot.set_opacity(1)
            box = row_widget(
                str(event.get("name") or "—"),
                f"{event.get('kind', '')} · {action} · {fmt_time(event.get('t'))}"
                + (f" · {event.get('reason')}" if event.get("reason") else ""),
                suffix=None,
                prefix=dot,
            )
            self.act_body.append(box)

    def _loaded_apps(self, data: dict) -> None:
        apps = list(data.get("apps") or [])
        policy = str(data.get("policy") or "allow")
        explicit = [a for a in apps if a.get("explicit")]
        blocked = [a for a in apps if str(a.get("action")) == "block"]
        self.apps_num.set_text(f"{len(explicit)}/{len(apps)}")
        clear(self.apps_chips)
        self.apps_chips.append(chip(f"{len(blocked)} blocked", "bad" if blocked else "dim"))
        self.apps_chips.append(chip(f"{len(apps) - len(blocked)} allowed", "ok"))
        self.apps_chips.append(chip(f"policy {policy}", "accent"))
        self._set_pill(self.apps_card, f"{len(apps)} seen", "dim")

        clear(self.apps_list)
        busy = sorted(apps, key=lambda a: -(int(a.get("conns") or 0)))[:5]
        if not busy:
            self.apps_list.append(label("No apps holding connections", ("rt-sub",)))
        for i, app in enumerate(busy):
            if i:
                self.apps_list.append(sep())
            action = str(app.get("action") or "allow")
            name = str(app.get("name") or f"uid {app.get('uid')}")
            self.apps_list.append(row_widget(
                name, f"{app.get('conns', 0)} conn · {fmt_num(app.get('packets', 0))} pkt",
                suffix=chip("block" if action == "block" else "allow",
                            "bad" if action == "block" else "ok")))

    def _loaded_stats(self, data: dict) -> None:
        top = list(data.get("top_blocked") or [])
        if top:
            self.hour_top.set_text(f"top blocked {top[0].get('domain')} · {fmt_num(top[0].get('count'))}")
        page = self.win.pages.get("stats")
        if isinstance(page, StatsPage):
            page.accept(data)

    def _on_start_stop(self, *_a) -> None:
        st = self.win.status or {}
        target = not bool(st.get("protected"))
        self.start_stop.set_sensitive(False)

        def done(_data) -> None:
            self.start_stop.set_sensitive(True)
            self.win.toast("Protection started" if target else "Protection stopped")
            self.win.poll(force=True)
            self.win.refresh_all()

        def failed(message: str) -> None:
            self.start_stop.set_sensitive(True)
            self.win.toast(message)

        api("POST", "/api/protected", {"on": target}, ok=done, err=failed)

    def _on_pause(self, *_a) -> None:
        dialog = Adw.MessageDialog.new(self.win, "Pause protection?",
                                       "Filtering stops now and restarts automatically. "
                                       "Keep the app open while paused.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("5", "5 min")
        dialog.add_response("15", "15 min")
        dialog.add_response("60", "1 hour")
        dialog.set_response_appearance("15", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def confirmed(_d, response: str) -> None:
            if response == "cancel":
                return
            minutes = int(response)
            api("POST", "/api/protected", {"on": False},
                ok=lambda _x: self._paused(minutes),
                err=lambda e: self.win.toast(e))

        dialog.connect("response", confirmed)
        dialog.present()

    def _paused(self, minutes: int) -> None:
        self.win.toast(f"Paused for {minutes} min — it resumes automatically")
        self.win.poll(force=True)

        def resume() -> bool:
            api("POST", "/api/protected", {"on": True},
                ok=lambda _x: (self.win.toast("Protection resumed"),
                               self.win.poll(force=True), self.win.refresh_all()))
            return False

        GLib.timeout_add_seconds(minutes * 60, resume)

    def _on_proxy_switch(self, switch, _prop) -> None:
        if self.proxy_sync:
            return
        target = switch.get_active()
        def failed(message: str) -> None:
            self.win.toast(message)
            self.proxy_sync = True
            switch.set_active(not target)
            self.proxy_sync = False

        api("POST", "/api/proxy/toggle", {"enabled": target},
            ok=lambda _d: (self.win.toast("Proxy enabled" if target else "Proxy disabled"),
                           self.win.refresh_all()),
            err=failed)


# --------------------------------------------------------------------------- #
# firewall / apps
# --------------------------------------------------------------------------- #
class FirewallPage(Page):
    title = "Firewall"
    icon = ICONS["firewall"]

    def build(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        root.set_margin_top(16)
        root.set_margin_bottom(8)
        root.set_margin_start(18)
        root.set_margin_end(18)

        # policy card ------------------------------------------------------
        policy_row = Gtk.Box(spacing=10)
        self.allow_btn = Gtk.ToggleButton(label="Allow by default")
        self.block_btn = Gtk.ToggleButton(label="Block by default")
        self.allow_btn.connect("clicked", lambda *_: self._set_policy("allow"))
        self.block_btn.connect("clicked", lambda *_: self._set_policy("block"))
        policy_row.append(linked(self.allow_btn, self.block_btn))
        self.policy_hint = label("—", ("rt-sub",))
        self.policy_hint.set_valign(Gtk.Align.CENTER)
        policy_row.append(self.policy_hint)
        bulk = Gtk.Box(spacing=6)
        block_all = Gtk.Button(label="Block all")
        block_all.connect("clicked", self._bulk, "block", "Block every app?")
        allow_all = Gtk.Button(label="Allow all")
        allow_all.connect("clicked", self._bulk, "allow", "Allow every app?")
        reset = Gtk.Button(label="Reset rules")
        reset.connect("clicked", self._reset_all)
        for btn in (block_all, allow_all, reset):
            btn.add_css_class("flat")
            bulk.append(btn)
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        policy_row.append(spacer)
        policy_row.append(bulk)
        pcard, pbody = card("DEFAULT POLICY", extra=None)
        pbody.append(policy_row)
        self.policy_counts = label("scanning apps…", ("rt-sub",))
        pbody.append(self.policy_counts)
        root.append(pcard)

        # toolbar ----------------------------------------------------------
        tools = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.search = Gtk.SearchEntry(placeholder_text="Search by name, uid or path")
        self.search.set_hexpand(True)
        self.search.connect("search-changed", self._on_search)
        bar = Gtk.Box(spacing=10)
        bar.append(self.search)
        self.spin = spinner()
        self.refresh_btn = icon_button("view-refresh-symbolic", "Rescan /proc", self._rescan)
        bar.append(self.refresh_btn)
        bar.append(self.spin)
        root.append(bar)

        chips = Gtk.Box(spacing=6)
        chips.add_css_class("rt-chips")
        self.filters: dict[str, Gtk.ToggleButton] = {}
        for i, (key, text) in enumerate((("all", "All"), ("allowed", "Allowed"),
                                         ("blocked", "Blocked"), ("explicit", "Explicit rules"))):
            btn = toggle_chip(text, active=(i == 0))
            btn.connect("toggled", self._on_filter, key)
            self.filters[key] = btn
            chips.append(btn)
        sort = Gtk.DropDown.new_from_strings(["Sort: name", "Sort: uid", "Sort: path"])
        sort.set_valign(Gtk.Align.CENTER)
        sort.connect("notify::selected", self._on_sort)
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        chips.append(spacer)
        chips.append(sort)
        self.sort_widget = sort
        root.append(chips)

        self.list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.list.add_css_class("rt-card")
        self.list.set_valign(Gtk.Align.START)
        scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(self.list)
        root.append(scroller)
        return root

    # -- data --------------------------------------------------------------
    def load(self) -> None:
        self.spin.start()
        self.get("/api/apps", ok=self._loaded, err=lambda e: (self.spin.stop(), self._fail(e)))

    def _loaded(self, data: dict) -> None:
        self.spin.stop()
        self.data = dict(data)
        self.apps = list(data.get("apps") or [])
        self.policy = str(data.get("policy") or "allow")
        self.allow_btn.set_active(self.policy == "allow")
        self.block_btn.set_active(self.policy == "block")
        self.policy_hint.set_text(
            "only apps you block are filtered" if self.policy == "allow"
            else "everything is filtered except apps you allow")
        self.render()

    def render(self) -> None:
        apps = getattr(self, "apps", [])
        policy = getattr(self, "policy", "allow")
        needle = self.search.get_text().strip().lower()
        flt = next((k for k, b in self.filters.items() if b.get_active()), "all")
        sort_idx = int(self.sort_widget.get_selected() or 0)
        rows = []
        for app in apps:
            action = str(app.get("action") or "allow")
            explicit = bool(app.get("explicit"))
            if flt == "allowed" and action == "block":
                continue
            if flt == "blocked" and action != "block":
                continue
            if flt == "explicit" and not explicit:
                continue
            name = str(app.get("name") or f"uid {app.get('uid')}")
            exe = str(app.get("exe") or "")
            if needle and needle not in name.lower() and needle not in exe.lower() \
                    and needle not in str(app.get("uid")):
                continue
            rows.append((name, app))
        if sort_idx == 1:
            rows.sort(key=lambda r: int(r[1].get("uid") or 0))
        elif sort_idx == 2:
            rows.sort(key=lambda r: str(r[1].get("exe") or ""))
        else:
            rows.sort(key=lambda r: r[0].lower())

        clear(self.list)
        if not rows:
            empty = label("No apps match this filter", ("rt-sub",))
            empty.set_margin_top(24)
            empty.set_margin_bottom(24)
            holder = Gtk.Box()
            holder.append(empty)
            self.list.append(holder)
        for name, app in rows:
            self.list.append(self._row(name, app))

        blocked = sum(1 for a in apps if str(a.get("action")) == "block")
        explicit = sum(1 for a in apps if a.get("explicit"))
        self.policy_counts.set_text(
            f"{len(rows)} shown · {len(apps)} discovered · "
            f"{blocked} blocked ({explicit} with explicit rules) · policy {policy}")

    def _row(self, name: str, app: dict) -> Gtk.Widget:
        uid = int(app.get("uid") or 0)
        action = str(app.get("action") or "allow")
        exe = str(app.get("exe") or "")
        subtitle = (f"uid {uid} · {exe or 'no path'} · {app.get('conns', 0)} conn · "
                    f"{fmt_num(app.get('packets', 0))} pkt")
        if app.get("dropped"):
            subtitle += f" · {fmt_num(app.get('dropped'))} dropped"
        if app.get("explicit"):
            subtitle += " · explicit rule"
        switch = Gtk.Switch(active=action == "block")
        switch.set_valign(Gtk.Align.CENTER)
        switch.connect("notify::active", self._on_switch, app)
        info = icon_button("dialog-information-symbolic", "App details",
                           lambda *_a, a=app: self._details(a))
        info.add_css_class("flat")
        box = row_widget(name, subtitle, suffix=None, prefix=Gtk.Image.new_from_icon_name(
            "application-x-executable-symbolic"))
        tail = Gtk.Box(spacing=8)
        tail.append(info)
        tail.append(switch)
        box.append(tail)
        holder = Gtk.Box()
        holder.add_css_class("rt-row")
        holder.append(box)
        return holder

    # -- actions -----------------------------------------------------------
    def _rescan(self, *_a) -> None:
        self.spin.start()
        self.post("/api/apps/refresh", {},
                  ok=lambda _d: self.load(),
                  err=lambda e: (self.spin.stop(), self._fail(e)))

    def _bulk(self, _btn, action: str, heading: str) -> None:
        dialog = Adw.MessageDialog.new(
            self.win, heading,
            "Explicit rules will be written for every discovered app. "
            "Use “Reset rules” to go back to the default policy only.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", "Apply")
        dialog.set_response_appearance(
            "go", Adw.ResponseAppearance.DESTRUCTIVE if action == "block"
            else Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.connect("response", self._bulk_confirmed, action)
        dialog.present()

    def _bulk_confirmed(self, dialog, response: str, action: str) -> None:
        if response != "go":
            return
        apps = list(getattr(self, "apps", []))
        self.spin.start()

        def work() -> None:
            try:
                for app in apps:
                    call("POST", "/api/apps", {"uid": int(app["uid"]), "action": action})
            except ApiError as exc:  # type: ignore[misc]
                GLib.idle_add(self._fail, str(exc))
            GLib.idle_add(self.load)
            GLib.idle_add(lambda: False)

        threading.Thread(target=work, daemon=True).start()
        self.win.toast(f"Setting {len(apps)} apps to {action}…")

    def _on_search(self, *_a) -> None:
        if getattr(self, "_search_src", None):
            GLib.source_remove(self._search_src)
        self._search_src = GLib.timeout_add(150, self._search_fire)

    def _search_fire(self) -> bool:
        self._search_src = None
        self.render()
        return False

    def _on_filter(self, button, key: str) -> None:
        if button.get_active():
            for other, btn in self.filters.items():
                if other != key:
                    btn.set_active(False)
            self.render()

    def _on_sort(self, *_a) -> None:
        self.render()

    def _on_switch(self, switch, _prop, app: dict) -> None:
        want_block = switch.get_active()
        current = str(app.get("action")) == "block"
        if want_block == current:
            return
        uid = int(app.get("uid"))
        action = "block" if want_block else "allow"

        def done(_d) -> None:
            self.win.toast(f"{app.get('name') or uid}: {action}")
            self.load()

        def failed(message: str) -> None:
            self.win.toast(message)
            switch.set_active(not want_block)

        api("POST", "/api/apps", {"uid": uid, "action": action}, ok=done, err=failed)

    def _set_policy(self, policy: str) -> None:
        if getattr(self, "policy", None) == policy:
            return

        def done(_d) -> None:
            self.win.toast(f"Default policy: {policy}")
            self.load()

        api("POST", "/api/policy", {"policy": policy}, ok=done,
            err=lambda e: (self.win.toast(e), self.load()))

    def _reset_all(self, *_a) -> None:
        dialog = Adw.MessageDialog.new(self.win, "Reset every app rule?",
                                       "Explicit block/allow rules for all apps will be removed. "
                                       "The default policy stays unchanged.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("reset", "Reset rules")
        dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.connect("response", self._reset_confirmed)
        dialog.present()

    def _reset_confirmed(self, dialog, response: str) -> None:
        if response != "reset":
            return
        uids = [int(a["uid"]) for a in getattr(self, "apps", []) if a.get("explicit")]
        self.spin.start()

        def work() -> None:
            try:
                for uid in uids:
                    call("DELETE", f"/api/apps/{uid}")
            except ApiError as exc:  # type: ignore[misc]
                GLib.idle_add(self._fail, str(exc))
            GLib.idle_add(self.load)
            GLib.idle_add(lambda: False)

        threading.Thread(target=work, daemon=True).start()
        self.win.toast(f"Removed {len(uids)} rules")

    def _details(self, app: dict) -> None:
        uid = int(app.get("uid") or 0)
        name = str(app.get("name") or f"uid {uid}")
        dialog = Adw.MessageDialog.new(self.win, esc(name), "")
        body = (f"uid {uid}\n{app.get('exe') or 'unknown path'}\n\n"
                f"action: {app.get('action')}  ·  explicit: {bool(app.get('explicit'))}\n"
                f"processes: {app.get('processes', 0)}  ·  connections: {app.get('conns', 0)}\n"
                f"packets: {fmt_num(app.get('packets', 0))}  ·  dropped: {fmt_num(app.get('dropped', 0))}")
        dialog.set_body(esc(body).replace("\n", "\n"))
        dialog.add_response("close", "Close")
        dialog.add_response("reset", "Reset rule")
        dialog.add_response("allow", "Allow")
        dialog.add_response("block", "Block")
        dialog.set_response_appearance("block", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_response_appearance("allow", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("close")
        dialog.set_close_response("close")
        dialog.connect("response", self._detail_response, app)
        dialog.present()

    def _detail_response(self, dialog, response: str, app: dict) -> None:
        uid = int(app.get("uid") or 0)
        if response == "reset":
            self.delete(f"/api/apps/{uid}", ok=lambda _d: (self.win.toast("Rule removed"),
                                                           self.load()))
        elif response in ("allow", "block"):
            api("POST", "/api/apps", {"uid": uid, "action": response},
                ok=lambda _d: (self.win.toast(f"{app.get('name') or uid}: {response}"),
                               self.load()))


# --------------------------------------------------------------------------- #
# dns: upstream, domain rules, blocklists, tester
# --------------------------------------------------------------------------- #
UPSTREAMS = ("system", "doh", "dot", "plain")
UPSTREAM_LABELS = ("System DNS", "DNS over HTTPS", "DNS over TLS", "Plain (UDP/TCP)")


class DnsPage(Page):
    title = "DNS"
    icon = ICONS["dns"]

    def build(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        root.set_margin_top(16)
        root.set_margin_bottom(8)
        root.set_margin_start(18)
        root.set_margin_end(18)

        # upstream ---------------------------------------------------------
        self.apply_up = Gtk.Button(label="Apply")
        self.apply_up.add_css_class("suggested-action")
        self.apply_up.connect("clicked", self._apply_upstream)
        self.listen_lbl = label("", ("rt-sub",))
        self.listen_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        up_tools = Gtk.Box(spacing=8)
        up_tools.append(self.listen_lbl)
        up_tools.append(self.apply_up)
        ucard, ubody = card("UPSTREAM RESOLVER", extra=up_tools)
        up_row = Gtk.Box(spacing=10)
        self.up_type = Gtk.DropDown.new_from_strings(list(UPSTREAM_LABELS))
        self.up_type.set_valign(Gtk.Align.CENTER)
        self.up_type.connect("notify::selected", self._on_upstream_type)
        up_row.append(self.up_type)
        self.up_url = Gtk.Entry(placeholder_text="https://dns.quad9.net/dns-query")
        self.up_url.set_hexpand(True)
        up_row.append(self.up_url)
        ubody.append(up_row)
        hijack_row = Gtk.Box(spacing=10)
        self.hijack = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.hijack.connect("notify::active", self._on_hijack)
        self.hijack_sync = False
        self.hijack_lbl = label("Redirect all port 53 traffic into the local resolver", ("rt-sub",))
        hijack_row.append(self.hijack_lbl)
        hijack_row.append(self.hijack)
        ubody.append(hijack_row)
        root.append(ucard)

        # domain rules -----------------------------------------------------
        entry_row = Gtk.Box(spacing=8)
        self.domain = Gtk.Entry(placeholder_text="example.com")
        self.domain.set_hexpand(True)
        self.domain.connect("activate", lambda *_: self._add_domain("block"))
        entry_row.append(self.domain)
        block_btn = Gtk.Button(label="Block")
        block_btn.add_css_class("destructive-action")
        block_btn.connect("clicked", lambda *_: self._add_domain("block"))
        allow_btn = Gtk.Button(label="Allow")
        allow_btn.add_css_class("suggested-action")
        allow_btn.connect("clicked", lambda *_: self._add_domain("allow"))
        entry_row.append(block_btn)
        entry_row.append(allow_btn)
        self.rules_total = label("", ("rt-sub",))
        rcard, rbody = card("DOMAIN RULES", extra=self.rules_total)
        rbody.append(entry_row)
        self.rules_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        rbody.append(self.rules_box)
        root.append(rcard)

        # blocklists -------------------------------------------------------
        self.list_spin = spinner()
        refresh_btn = icon_button("view-refresh-symbolic", "Re-download all enabled lists",
                                  lambda *_: self._refresh_lists())
        self.lists_total = label("—", ("rt-sub",))
        head_tools = Gtk.Box(spacing=8)
        head_tools.append(self.lists_total)
        head_tools.append(refresh_btn)
        head_tools.append(self.list_spin)
        bcard, bbody = card("BLOCKLISTS", extra=head_tools)
        self.cats_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        bbody.append(self.cats_box)
        custom_head = Gtk.Box(spacing=8)
        custom_head.set_margin_top(12)
        custom_head.append(label("CUSTOM LISTS", ("rt-section",)))
        self.custom_total = label("", ("rt-sub",))
        custom_head.append(self.custom_total)
        bbody.append(custom_head)
        self.custom_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        bbody.append(self.custom_box)
        add_row = Gtk.Box(spacing=8)
        self.custom_url = Gtk.Entry(placeholder_text="https://example.com/list.txt")
        self.custom_url.set_hexpand(True)
        add_btn = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Add custom list")
        add_btn.connect("clicked", lambda *_: self._add_custom())
        self.custom_url.connect("activate", lambda *_: self._add_custom())
        add_row.append(self.custom_url)
        add_row.append(add_btn)
        bbody.append(add_row)
        root.append(bcard)

        # tester -----------------------------------------------------------
        test_row = Gtk.Box(spacing=8)
        self.test_domain = Gtk.Entry(placeholder_text="doubleclick.net")
        self.test_domain.set_hexpand(True)
        self.test_domain.connect("activate", lambda *_: self._test())
        test_btn = Gtk.Button(label="Test")
        test_btn.connect("clicked", lambda *_: self._test())
        test_row.append(self.test_domain)
        test_row.append(test_btn)
        self.test_result = label("Check whether a domain is blocked, and by what.", ("rt-sub",))
        self.test_result.set_wrap(True)
        tcard, tbody = card("TEST A DOMAIN")
        tbody.append(test_row)
        tbody.append(self.test_result)
        root.append(tcard)
        return self._scroll(root)

    def _scroll(self, child: Gtk.Widget) -> Gtk.Widget:
        scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(child)
        return scroller

    # -- load --------------------------------------------------------------
    def load(self) -> None:
        self.get("/api/dns", ok=self._loaded_dns)
        self.get("/api/blocklists", ok=self._loaded_lists)

    def _loaded_dns(self, data: dict) -> None:
        self.data = dict(data)
        upstream = data.get("upstream") or {}
        kind = str(upstream.get("type") or "system")
        if kind in UPSTREAMS:
            self.up_type.set_selected(UPSTREAMS.index(kind))
        self.up_url.set_text(str(upstream.get("url") or ""))
        self.hijack_sync = True
        self.hijack.set_active(bool(data.get("hijack")))
        self.hijack_sync = False
        self.listen_lbl.set_text(f"listening {data.get('listen') or '—'} · "
                                 f"{fmt_num(data.get('queries', 0))} queries · "
                                 f"{fmt_num(data.get('blocked', 0))} blocked")
        self._render_rules(data)

    def _render_rules(self, data: dict) -> None:
        clear(self.rules_box)
        blocked = list(data.get("block") or [])
        allowed = list(data.get("allow") or [])
        self.rules_total.set_text(f"{len(blocked)} blocked · {len(allowed)} allowed")
        if not blocked and not allowed:
            empty = label("No manual rules yet — add one above.", ("rt-sub",))
            empty.set_margin_top(6)
            empty.set_margin_bottom(6)
            self.rules_box.append(empty)
            return
        for kind, domains in (("bad", blocked), ("ok", allowed)):
            for domain in domains:
                suffix = Gtk.Box(spacing=6)
                suffix.append(chip("block" if kind == "bad" else "allow", kind))
                remove = icon_button("user-trash-symbolic", "Remove rule",
                                     lambda *_a, d=domain: self._remove_domain(d))
                remove.add_css_class("flat")
                suffix.append(remove)
                self.rules_box.append(row_widget(domain, None, suffix=suffix))
                self.rules_box.append(sep())

    def _loaded_lists(self, data: dict) -> None:
        self.data_lists = dict(data)
        cats = list(data.get("categories") or [])
        custom = list(data.get("custom") or [])
        totals = data.get("totals") or {}
        enabled = sum(1 for c in cats if c.get("enabled")) + \
            sum(1 for c in custom if c.get("enabled"))
        self.lists_total.set_text(
            f"{enabled} enabled · {fmt_num(totals.get('domains', 0))} domains")

        clear(self.cats_box)
        for i, cat in enumerate(cats):
            if i:
                self.cats_box.append(sep())
            domains = int(cat.get("domains") or 0)
            source = str(cat.get("source") or "").rsplit("/", 1)[-1]
            parts = []
            if domains:
                parts.append(f"{fmt_num(domains)} domains")
            if source:
                parts.append(source)
            subtitle = " · ".join(parts) or "no domain count yet"
            if cat.get("last_error"):
                subtitle += f" · error: {str(cat['last_error'])[:60]}"
            switch = Gtk.Switch(active=bool(cat.get("enabled")))
            switch.set_valign(Gtk.Align.CENTER)
            switch.connect("notify::active", self._on_cat_toggle, cat)
            self.cats_box.append(row_widget(str(cat.get("name") or cat.get("id")),
                                            subtitle, suffix=switch))

        clear(self.custom_box)
        if not custom:
            self.custom_box.append(label("No custom lists", ("rt-sub",)))
        for entry in custom:
            domains = int(entry.get("domains") or 0)
            subtitle = str(entry.get("url") or "")
            if domains:
                subtitle = f"{fmt_num(domains)} domains · {subtitle}"
            if entry.get("last_error"):
                subtitle += f" · error: {str(entry['last_error'])[:60]}"
            suffix = Gtk.Box(spacing=6)
            remove = icon_button("user-trash-symbolic", "Delete list",
                                 lambda *_a, cid=str(entry.get("id")): self._remove_custom(cid))
            remove.add_css_class("flat")
            suffix.append(remove)
            switch = Gtk.Switch(active=bool(entry.get("enabled")))
            switch.set_valign(Gtk.Align.CENTER)
            switch.connect("notify::active", self._on_custom_toggle, entry)
            suffix.append(switch)
            self.custom_box.append(row_widget(str(entry.get("url")), subtitle, suffix=suffix))

    # -- actions -----------------------------------------------------------
    def _on_upstream_type(self, *_a) -> None:
        pass  # applied explicitly with the Apply button

    def _apply_upstream(self, *_a) -> None:
        kind = UPSTREAMS[int(self.up_type.get_selected() or 0)]
        payload = {"type": kind, "url": self.up_url.get_text().strip()}
        self.apply_up.set_sensitive(False)
        self.post("/api/dns/upstream", payload,
                  ok=lambda _d: (self.apply_up.set_sensitive(True),
                                 self.win.toast("Upstream updated"), self.load()),
                  err=lambda e: (self.apply_up.set_sensitive(True), self._fail(e)))

    def _on_hijack(self, switch, _prop) -> None:
        if self.hijack_sync:
            return
        target = switch.get_active()
        self.post("/api/dns/hijack", {"enabled": target},
                  ok=lambda _d: (self.win.toast("Port 53 redirect " + ("on" if target else "off")),
                                 self.load()),
                  err=lambda e: (self._fail(e), setattr(self, "hijack_sync", True),
                                 switch.set_active(not target),
                                 setattr(self, "hijack_sync", False)))

    def _add_domain(self, action: str) -> None:
        domain = self.domain.get_text().strip().lower().lstrip(".")
        if not domain:
            self.win.toast("Enter a domain first")
            return
        self.post("/api/dns/domain", {"domain": domain, "action": action},
                  ok=lambda _d: (self.domain.set_text(""), self.win.toast(f"{domain}: {action}"),
                                 self.load()),
                  err=lambda e: self._fail(e))

    def _remove_domain(self, domain: str) -> None:
        self.delete(f"/api/dns/domain/{urllib.parse.quote(domain, safe='')}",
                    ok=lambda _d: (self.win.toast(f"Removed {domain}"), self.load()))

    def _on_cat_toggle(self, switch, _prop, cat: dict) -> None:
        target = switch.get_active()
        self.post("/api/blocklists", {"id": str(cat.get("id")), "enabled": target},
                  ok=lambda _d: self.load(),
                  err=lambda e: (self._fail(e), switch.set_active(not target)))

    def _on_custom_toggle(self, switch, _prop, entry: dict) -> None:
        target = switch.get_active()
        self.post("/api/blocklists", {"id": str(entry.get("id")), "enabled": target},
                  ok=lambda _d: self.load(),
                  err=lambda e: (self._fail(e), switch.set_active(not target)))

    def _add_custom(self) -> None:
        url = self.custom_url.get_text().strip()
        if not url.startswith(("http://", "https://")):
            self.win.toast("Enter an http(s) URL")
            return
        self.post("/api/blocklists/custom", {"url": url, "enabled": True},
                  ok=lambda _d: (self.custom_url.set_text(""), self.win.toast("List added"),
                                 self.load()))

    def _remove_custom(self, item_id: str) -> None:
        self.delete(f"/api/blocklists/custom/{urllib.parse.quote(item_id, safe='')}",
                    ok=lambda _d: (self.win.toast("List removed"), self.load()))

    def _refresh_lists(self, *_a) -> None:
        self.list_spin.start()
        self.post("/api/blocklists/refresh", {},
                  ok=lambda _d: (self.list_spin.stop(), self.win.toast("Lists refreshed"),
                                 self.load()),
                  err=lambda e: (self.list_spin.stop(), self._fail(e)),
                  timeout=300)

    def _test(self, *_a) -> None:
        domain = self.test_domain.get_text().strip()
        if not domain:
            return
        self.test_result.set_text("testing…")
        self.post("/api/blocklists/test", {"domain": domain},
                  ok=lambda d: self._test_done(domain, d),
                  err=lambda e: setattr(self.test_result, "label", f"error: {e}"))

    def _test_done(self, domain: str, data: dict) -> None:
        blocked = bool(data.get("blocked"))
        reason = data.get("reason")
        text = f"{domain} is {'BLOCKED' if blocked else 'ALLOWED'}"
        if reason:
            text += f" · {reason}"
        elif blocked:
            text += " · by an enabled list"
        self.test_result.set_text(text)
        self.test_result.add_css_class("bad" if blocked else "ok")


# --------------------------------------------------------------------------- #
# logs: DNS query log + activity feed
# --------------------------------------------------------------------------- #
class LogsPage(Page):
    title = "Logs"
    icon = ICONS["logs"]
    auto_refresh = True

    def build(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        root.set_margin_top(12)
        root.set_margin_bottom(8)
        root.set_margin_start(18)
        root.set_margin_end(18)

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        switcher = Gtk.StackSwitcher(stack=self.stack)
        switcher.set_halign(Gtk.Align.CENTER)

        top = Gtk.Box(spacing=10)
        holder = Gtk.Box()
        holder.set_hexpand(True)
        holder.append(switcher)
        top.append(holder)
        self.search = Gtk.SearchEntry(placeholder_text="Search domains, apps, IPs")
        self.search.set_hexpand(True)
        self.search.connect("search-changed", self._on_search)
        top.append(self.search)
        self.clear_btn = Gtk.Button(label="Clear DNS log")
        self.clear_btn.connect("clicked", self._clear_log)
        top.append(self.clear_btn)
        top.append(icon_button("view-refresh-symbolic", "Refresh (Ctrl+R)",
                               lambda *_: self.load()))
        root.append(top)

        # filters ----------------------------------------------------------
        self.dns_filter = "all"
        self.act_filter = "all"
        self.query = ""
        self.activity: list[dict] = []
        dns_chips = Gtk.Box(spacing=6)
        for key, text in (("all", "All"), ("blocked", "Blocked"), ("allowed", "Allowed")):
            btn = toggle_chip(text, active=(key == "all"))
            btn.connect("toggled", self._on_filter, "dns", key)
            dns_chips.append(btn)
        act_chips = Gtk.Box(spacing=6)
        for key, text in (("all", "All"), ("dns", "DNS"), ("firewall", "Firewall"),
                          ("proxy", "Proxy")):
            btn = toggle_chip(text, active=(key == "all"))
            btn.connect("toggled", self._on_filter, "act", key)
            act_chips.append(btn)
        self.dns_chips = dns_chips
        self.act_chips = act_chips

        dns_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        dns_page.append(dns_chips)
        self.dns_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        dns_list_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        dns_list_card.add_css_class("rt-card")
        dns_list_card.append(self.dns_list)
        dns_scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        holder2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        holder2.append(dns_page)
        holder2.append(dns_list_card)
        dns_scroll.set_child(holder2)
        dns_scroll.set_vexpand(True)
        self.stack.add_named(dns_scroll, "dns")
        self.stack.get_page(dns_scroll).set_title("DNS log")

        act_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        act_page.append(act_chips)
        self.act_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        act_card_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        act_card_box.add_css_class("rt-card")
        act_card_box.append(self.act_list)
        act_page.append(act_card_box)
        act_scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        act_scroll.set_child(act_page)
        act_scroll.set_vexpand(True)
        self.stack.add_named(act_scroll, "activity")
        self.stack.get_page(act_scroll).set_title("Activity")
        self.stack.set_visible_child_name("dns")
        self.stack.connect("notify::visible-child-name", self._on_tab)
        root.append(self.stack)
        return root

    def _on_tab(self, *_a) -> None:
        self.clear_btn.set_sensitive(self.stack.get_visible_child_name() == "dns")

    def _on_search(self, *_a) -> None:
        self.query = self.search.get_text().strip().lower()
        self._loaded_dns(self.data)
        self._render_activity()

    def load(self) -> None:
        self.get("/api/dns", ok=self._loaded_dns)
        self.get("/api/activity?limit=200", ok=self._loaded_activity)

    def _loaded_dns(self, data: dict) -> None:
        self.data = dict(data)
        entries = list(data.get("log") or [])
        filter_key = self.dns_filter
        clear(self.dns_list)
        shown = 0
        for entry in entries:
            blocked = bool(entry.get("blocked"))
            if filter_key == "blocked" and not blocked:
                continue
            if filter_key == "allowed" and blocked:
                continue
            if self.query and self.query not in str(entry.get("name") or "").lower() \
                    and self.query not in str(entry.get("reason") or "").lower():
                continue
            shown += 1
            if shown > 200:
                break
            action = "block" if not blocked else "allow"
            btn = Gtk.Button(label=action)
            btn.add_css_class("flat")
            btn.add_css_class("pill")
            btn.connect("clicked", self._quick_rule, str(entry.get("name") or ""), action)
            dot = Gtk.Label(label="●")
            dot.add_css_class("bad" if blocked else "ok")
            subtitle = (f"{entry.get('type', 'A')} · {'blocked' if blocked else 'allowed'} · "
                        f"{entry.get('client') or '—'} · {fmt_time(entry.get('t'))}")
            if entry.get("reason"):
                subtitle += f" · {entry['reason']}"
            self.dns_list.append(row_widget(str(entry.get("name") or "—"), subtitle,
                                            suffix=btn, prefix=dot))
            self.dns_list.append(sep())
        if not shown:
            empty = label("No queries match this filter", ("rt-sub",))
            empty.set_margin_top(16)
            self.dns_list.append(empty)

    def _loaded_activity(self, data: dict) -> None:
        self.activity = list(data.get("events") or [])
        self._render_activity()

    def _render_activity(self) -> None:
        clear(self.act_list)
        shown = 0
        for event in getattr(self, "activity", []):
            if self.act_filter != "all" and str(event.get("kind")) != self.act_filter:
                continue
            if self.query and self.query not in str(event.get("name") or "").lower() \
                    and self.query not in str(event.get("reason") or "").lower() \
                    and self.query not in str(event.get("app") or "").lower():
                continue
            shown += 1
            if shown > 200:
                break
            action = str(event.get("action") or "")
            blocked = action in ("blocked", "drop", "block")
            dot = Gtk.Label(label="●")
            dot.add_css_class("bad" if blocked else "ok")
            subtitle = (f"{event.get('kind', '')} · {action} · {fmt_time(event.get('t'))}"
                        + (f" · {event.get('reason')}" if event.get("reason") else "")
                        + (f" · uid {event.get('uid')}" if event.get("uid") else ""))
            self.act_list.append(row_widget(str(event.get("name") or "—"), subtitle, prefix=dot))
            self.act_list.append(sep())
        if not shown:
            empty = label("No events match this filter", ("rt-sub",))
            empty.set_margin_top(16)
            self.act_list.append(empty)

    def _on_filter(self, button, group: str, key: str) -> None:
        if not button.get_active():
            return
        box = self.dns_chips if group == "dns" else self.act_chips
        for child in box:
            if isinstance(child, Gtk.ToggleButton) and child is not button:
                child.set_active(False)
        if group == "dns":
            self.dns_filter = key
            self._loaded_dns(self.data)
        else:
            self.act_filter = key
            self._render_activity()

    def _quick_rule(self, _btn, domain: str, action: str) -> None:
        if not domain:
            return
        api("POST", "/api/dns/domain", {"domain": domain, "action": action},
            ok=lambda _d: (self.win.toast(f"{domain}: {action}"), self.load()))

    def _clear_log(self, *_a) -> None:
        dialog = Adw.MessageDialog.new(self.win, "Clear the DNS query log?",
                                       "The in-memory query log will be emptied.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("clear", "Clear log")
        dialog.set_response_appearance("clear", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def confirmed(_d, response: str) -> None:
            if response == "clear":
                api("POST", "/api/dns/clearlog", {},
                    ok=lambda _x: (self.win.toast("Log cleared"), self.load()))

        dialog.connect("response", confirmed)
        dialog.present()


# --------------------------------------------------------------------------- #
# stats
# --------------------------------------------------------------------------- #
class StatsPage(Page):
    title = "Stats"
    icon = ICONS["stats"]
    auto_refresh = True

    def build(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        root.set_margin_top(16)
        root.set_margin_bottom(8)
        root.set_margin_start(18)
        root.set_margin_end(18)

        tiles = Gtk.Box(spacing=14)
        self.tile_total, body = card("QUERIES · 60 MIN", tight=True)
        self.num_total = label("—", ("rt-num",))
        body.append(self.num_total)
        tiles.append(self.tile_total)
        self.tile_total.set_hexpand(True)
        self.tile_blocked, body = card("BLOCKED · 60 MIN", tight=True)
        self.num_blocked = label("—", ("rt-num",))
        body.append(self.num_blocked)
        tiles.append(self.tile_blocked)
        self.tile_blocked.set_hexpand(True)
        self.tile_rate, body = card("BLOCK RATE", tight=True)
        self.num_rate = label("—", ("rt-num",))
        body.append(self.num_rate)
        tiles.append(self.tile_rate)
        self.tile_rate.set_hexpand(True)
        self.tile_top, body = card("TOP BLOCKED", tight=True)
        self.num_top = label("—", ("rt-num small",))
        self.num_top.set_ellipsize(Pango.EllipsizeMode.END)
        body.append(self.num_top)
        tiles.append(self.tile_top)
        self.tile_top.set_hexpand(True)
        root.append(tiles)

        chart_card, chart_body = card("QUERIES PER MINUTE — LAST HOUR")
        self.legend = Gtk.Box(spacing=8)
        self.legend.append(chip("remaining", "dim"))
        self.legend.append(chip("blocked", "bad"))
        chart_card.get_first_child().append(self.legend)
        self.chart_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.chart_bars = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=3,
                                  valign=Gtk.Align.END)
        self.chart_bars.set_size_request(-1, 190)
        self.chart_axis = Gtk.Box(spacing=10)
        left = label("60 minutes ago", ("rt-sub",))
        self.chart_peak = label("", ("rt-sub",))
        self.chart_peak.set_xalign(1)
        now = label("now", ("rt-sub",))
        self.chart_axis.append(left)
        mid = Gtk.Box()
        mid.set_hexpand(True)
        self.chart_axis.append(mid)
        self.chart_axis.append(self.chart_peak)
        self.chart_axis.append(now)
        self.chart_box.append(self.chart_bars)
        self.chart_box.append(self.chart_axis)
        chart_body.append(self.chart_box)
        self.chart_empty = label("No queries in this window yet.", ("rt-sub",))
        chart_body.append(self.chart_empty)
        root.append(chart_card)
        cols = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        top_card, top_body = card("MOST BLOCKED DOMAINS")
        self.top_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        top_body.append(self.top_box)
        cols.append(top_card)
        top_card.set_hexpand(True)

        type_card, type_body = card("QUERY TYPES")
        self.type_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        type_body.append(self.type_box)
        cols.append(type_card)
        type_card.set_hexpand(True)
        root.append(cols)

        self.series: list[dict] = []
        self.top_blocked: list[dict] = []
        self.by_type: dict = {}
        scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(root)
        return scroller

    def load(self) -> None:
        self.get("/api/stats", ok=self.accept)

    def accept(self, data: dict) -> None:
        self.data = dict(data)
        self.series = list(data.get("series") or [])
        self.top_blocked = list(data.get("top_blocked") or [])
        self.by_type = dict(data.get("by_type") or {})
        total = sum(int(s.get("total") or 0) for s in self.series)
        blocked = sum(int(s.get("blocked") or 0) for s in self.series)
        self.num_total.set_text(fmt_num(total))
        self.num_blocked.set_text(fmt_num(blocked))
        self.num_rate.set_text(f"{(blocked / total * 100):.1f}%" if total else "0%")
        self.num_top.set_text(str(self.top_blocked[0].get("domain")) if self.top_blocked else "—")

        clear(self.top_box)
        if not self.top_blocked:
            self.top_box.append(label("Nothing blocked yet", ("rt-sub",)))
        for i, entry in enumerate(self.top_blocked[:10]):
            if i:
                self.top_box.append(sep())
            self.top_box.append(row_widget(str(entry.get("domain")),
                                           f"{fmt_num(entry.get('count'))} queries blocked",
                                           suffix=chip(f"{fmt_num(entry.get('count'))}", "bad")))

        clear(self.type_box)
        by_type = self.by_type
        type_total = sum(int(v or 0) for v in by_type.values()) or 1
        for name, count in sorted(by_type.items(), key=lambda kv: -int(kv[1] or 0))[:8]:
            value = int(count or 0)
            bar = Gtk.ProgressBar(fraction=min(1.0, value / type_total))
            bar.set_valign(Gtk.Align.CENTER)
            bar.set_size_request(150, -1)
            unit = "query" if value == 1 else "queries"
            self.type_box.append(row_widget(str(name), f"{fmt_num(value)} {unit} · "
                                           f"{value / type_total * 100:.1f}%", suffix=bar))
        self._draw_bars()

    def _draw_bars(self) -> None:
        clear(self.chart_bars)
        series = self.series or []
        peak = max([int(s.get("total") or 0) for s in series] + [1])
        self.chart_peak.set_text(f"peak {peak}/min")
        self.chart_empty.set_visible(not series)
        self.chart_bars.set_visible(bool(series))
        for point in series:
            total = int(point.get("total") or 0)
            blocked = int(point.get("blocked") or 0)
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            column.set_valign(Gtk.Align.END)
            column.set_hexpand(True)
            rest = max(0, total - blocked)
            h_rest = int(190 * (rest / peak))
            h_block = int(190 * (blocked / peak))
            if h_rest or not h_block:
                spacer = Gtk.Box()
                spacer.set_size_request(-1, max(h_rest, 1 if not total else 1))
                spacer.add_css_class("rt-chart-rest")
                spacer.set_hexpand(True)
                column.append(spacer)
            if h_block:
                bar = Gtk.Box()
                bar.set_size_request(-1, max(h_block, 3))
                bar.add_css_class("rt-chart-blocked")
                bar.set_hexpand(True)
                column.append(bar)
            if not total:
                column.append(Gtk.Box())
            self.chart_bars.append(column)


# --------------------------------------------------------------------------- #
# proxy
# --------------------------------------------------------------------------- #
PROXY_TYPES = ("http", "socks5")


class ProxyPage(Page):
    title = "Proxy"
    icon = ICONS["proxy"]

    def build(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        root.set_margin_top(16)
        root.set_margin_bottom(8)
        root.set_margin_start(18)
        root.set_margin_end(18)

        self.enable = Gtk.Switch()
        self.enable.set_valign(Gtk.Align.CENTER)
        self.enable.connect("notify::active", self._on_toggle)
        self.sync = False
        head_tools = Gtk.Box(spacing=8)
        self.proxy_pill = chip("inactive", "dim")
        head_tools.append(self.proxy_pill)
        head_tools.append(self.enable)
        scard, sbody = card("OUTBOUND PROXY", extra=head_tools)
        self.status_line = label("—", ("rt-num small",))
        sbody.append(self.status_line)
        self.status_sub = label("—", ("rt-sub",))
        sbody.append(self.status_sub)
        self.status_err = label("", ("rt-sub",))
        self.status_err.set_ellipsize(Pango.EllipsizeMode.END)
        sbody.append(self.status_err)
        root.append(scard)

        fcard, fbody = card("ENDPOINT")
        grid = Gtk.Grid(column_spacing=14, row_spacing=8)
        self.type = Gtk.DropDown.new_from_strings(list(PROXY_TYPES))
        self.type.set_valign(Gtk.Align.CENTER)
        self.host = Gtk.Entry(placeholder_text="proxy.example.com")
        self.port = Gtk.SpinButton.new_with_range(0, 65535, 1)
        self.user = Gtk.Entry(placeholder_text="optional")
        self.password = Gtk.PasswordEntry()
        self.password.set_show_peek_icon(True)
        if hasattr(self.password, "set_placeholder_text"):
            self.password.set_placeholder_text("optional")
        self.bypass = Gtk.Switch(valign=Gtk.Align.CENTER, halign=Gtk.Align.START)
        self.bypass.set_active(True)
        self.bypass_domains = Gtk.Entry(placeholder_text="*.local, 10.0.0.0/8")
        grid.attach(label("Protocol", ("rt-sub",)), 0, 0, 1, 1)
        grid.attach(self.type, 1, 0, 1, 1)
        grid.attach(label("Host", ("rt-sub",)), 2, 0, 1, 1)
        grid.attach(self.host, 3, 0, 1, 1)
        grid.attach(label("Port", ("rt-sub",)), 0, 1, 1, 1)
        grid.attach(self.port, 1, 1, 1, 1)
        grid.attach(label("Username", ("rt-sub",)), 2, 1, 1, 1)
        grid.attach(self.user, 3, 1, 1, 1)
        grid.attach(label("Password", ("rt-sub",)), 0, 2, 1, 1)
        grid.attach(self.password, 1, 2, 1, 1)
        grid.attach(label("Bypass LAN", ("rt-sub",)), 2, 2, 1, 1)
        grid.attach(self.bypass, 3, 2, 1, 1)
        grid.attach(label("Bypass domains", ("rt-sub",)), 0, 3, 1, 1)
        self.bypass_domains.set_hexpand(True)
        grid.attach(self.bypass_domains, 1, 3, 3, 1)
        fbody.append(grid)
        save_box = Gtk.Box(spacing=10)
        save = Gtk.Button(label="Save proxy settings")
        save.add_css_class("suggested-action")
        save.connect("clicked", lambda *_: self._save())
        save_box.append(save)
        fbody.append(save_box)
        root.append(fcard)
        return self._scroll(root)

    def _scroll(self, child: Gtk.Widget) -> Gtk.Widget:
        scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(child)
        return scroller

    def load(self) -> None:
        self.get("/api/proxy", ok=self._loaded)

    def _loaded(self, data: dict) -> None:
        self.data = dict(data)
        kinds = list(PROXY_TYPES)
        kind = str(data.get("type") or "http")
        self.type.set_selected(kinds.index(kind) if kind in kinds else 0)
        self.host.set_text(str(data.get("host") or ""))
        self.port.set_value(int(data.get("port") or 0))
        self.user.set_text(str(data.get("username") or ""))
        self.bypass.set_active(bool(data.get("bypass_lan")))
        self.bypass_domains.set_text(", ".join(str(d) for d in (data.get("bypass_domains") or [])))
        self.sync = True
        self.enable.set_active(bool(data.get("enabled")))
        self.sync = False
        endpoint = str(data.get("endpoint") or "")
        if data.get("enabled"):
            self.status_line.set_text(endpoint or "active")
            self.status_sub.set_text(f"{data.get('type', 'http')} · "
                                     f"{fmt_num(data.get('relayed', 0))} relayed · "
                                     f"{fmt_num(data.get('active', 0))} open connections")
        else:
            self.status_line.set_text("inactive")
            self.status_sub.set_text("Traffic leaves this machine directly. "
                                     "Save an endpoint and enable it to route everything.")
        err = str(data.get("last_error") or "")
        self.status_err.set_text(f"error: {err[:90]}" if err else "")

    def _on_toggle(self, switch, _prop) -> None:
        if self.sync:
            return
        target = switch.get_active()
        self.post("/api/proxy/toggle", {"enabled": target},
                  ok=lambda _d: (self.win.toast("Proxy " + ("enabled" if target else "disabled")),
                                 self.load()),
                  err=lambda e: (self._fail(e), setattr(self, "sync", True),
                                 switch.set_active(not target),
                                 setattr(self, "sync", False)))

    def _save(self, *_a) -> None:
        password = self.password.get_text() if hasattr(self.password, "get_text") else ""
        payload = {
            "type": PROXY_TYPES[int(self.type.get_selected() or 0)],
            "host": self.host.get_text().strip(),
            "port": int(self.port.get_value()),
            "username": self.user.get_text().strip(),
            "bypass_lan": self.bypass.get_active(),
            "bypass_domains": [d.strip() for d in self.bypass_domains.get_text().split(",")
                               if d.strip()],
            "enabled": bool(self.data.get("enabled")),
        }
        if password:
            payload["password"] = password
        self.post("/api/proxy", payload,
                  ok=lambda _d: (self.win.toast("Proxy settings saved"),
                                 self.password.set_text(""), self.load()))


# --------------------------------------------------------------------------- #
# settings / about
# --------------------------------------------------------------------------- #
class SettingsPage(Page):
    title = "Settings"
    icon = ICONS["settings"]

    def build(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        root.set_margin_top(16)
        root.set_margin_bottom(8)
        root.set_margin_start(18)
        root.set_margin_end(18)

        acard, abody = card("APPEARANCE")
        theme_row = Gtk.Box(spacing=10)
        self.theme = Gtk.DropDown.new_from_strings(["System", "Light", "Dark"])
        self.theme.set_valign(Gtk.Align.CENTER)
        self.theme.connect("notify::selected", self._on_theme)
        self.theme_sync = False
        theme_row.append(label("Theme", ("rt-sub",)))
        theme_row.append(self.theme)
        abody.append(theme_row)
        root.append(acard)

        dcard, dbody = card("DAEMON")
        self.start_protected = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.start_protected.connect("notify::active", self._on_start_protected)
        self.start_sync = False
        dbody.append(row_widget("Start protected on boot",
                                "the service starts with protection enabled",
                                suffix=self.start_protected))
        dbody.append(sep())
        log_row = Gtk.Box(spacing=10)
        self.log_level = Gtk.DropDown.new_from_strings(["debug", "info", "warn"])
        self.log_level.set_valign(Gtk.Align.CENTER)
        self.log_level.connect("notify::selected", self._on_log_level)
        self.log_sync = False
        log_row.append(label("Log level", ("rt-sub",)))
        log_row.append(self.log_level)
        dbody.append(log_row)
        dbody.append(sep())
        self.listen_row = label("listen —", ("rt-sub",))
        dbody.append(self.listen_row)
        dbody.append(sep())
        self.mode_row = label("mode —", ("rt-sub",))
        dbody.append(self.mode_row)
        root.append(dcard)

        scard, sbody = card("SESSION")
        web_row = Gtk.Box(spacing=8)
        web_btn = Gtk.Button(label="Open web UI")
        web_btn.connect("clicked", lambda *_: self.win.open_web_ui())
        copy_btn = Gtk.Button(label="Copy URL")
        copy_btn.connect("clicked", lambda *_: self.win.copy_ui_url())
        web_row.append(web_btn)
        web_row.append(copy_btn)
        sbody.append(web_row)
        sbody.append(sep())
        self.token_row = label("token —", ("rt-sub",))
        sbody.append(self.token_row)
        root.append(scard)

        icard, ibody = card("ABOUT")
        self.info_rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        ibody.append(self.info_rows)
        link = Gtk.LinkButton(uri="https://github.com/kusal630/rethink-root-linux",
                              label="github.com/kusal630/rethink-root-linux")
        link.set_halign(Gtk.Align.START)
        ibody.append(link)
        ibody.append(label("Apache-2.0 · local daemon · no telemetry", ("rt-sub",)))
        root.append(icard)
        return self._scroll(root)

    def _scroll(self, child: Gtk.Widget) -> Gtk.Widget:
        scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(child)
        return scroller

    def load(self) -> None:
        self.get("/api/settings", ok=self._loaded)
        self.get("/api/status", ok=self._loaded_status)

    def _loaded_status(self, data: dict) -> None:
        self.status = dict(data)
        self.win.status = data
        self.win.paint_header()
        if getattr(self, "data", None):
            self._render_info()

    def _render_info(self) -> None:
        data = self.data or {}
        st = getattr(self, "status", {}) or {}
        fw = st.get("firewall") or {}
        if fw.get("enabled"):
            firewall = "active" + (f" · {fw.get('error')}" if fw.get("error") else "")
        else:
            firewall = "off" + (f" · {fw.get('error')}" if fw.get("error") else "")
        host = st.get("host") or {}
        rows = [
            ("Version", str(data.get("version") or st.get("version") or "—")),
            ("Uptime", fmt_duration(up) if (up := (data.get("uptime_s")
                                    if data.get("uptime_s") is not None
                                    else st.get("uptime_s"))) is not None else "—"),
            ("Running as", str(st.get("running_as") or "—")),
            ("Kernel", str(host.get("kernel") or "—")),
            ("System", str(host.get("os") or "—")),
            ("Python", str(host.get("python") or "—")),
            ("UID", str(host.get("uid") if host.get("uid") is not None else "—")),
            ("Firewall", firewall),
        ]
        clear(self.info_rows)
        for i, (title, value) in enumerate(rows):
            if i:
                self.info_rows.append(sep())
            self.info_rows.append(row_widget(title, value))

    def _loaded(self, data: dict) -> None:
        self.data = dict(data)
        theme = str(data.get("theme") or "dark")
        self.theme_sync = True
        self.theme.set_selected(1 if theme == "light" else 2 if theme == "dark" else 0)
        self.theme_sync = False
        level = str(data.get("log_level") or "info")
        self.log_sync = True
        self.log_level.set_selected(["debug", "info", "warn"].index(level)
                                    if level in ("debug", "info", "warn") else 1)
        self.log_sync = False
        self.start_sync = True
        self.start_protected.set_active(bool(data.get("start_protected")))
        self.start_sync = False
        self.listen_row.set_text(f"API listen {data.get('listen', '—')} · "
                                 f"token {data.get('token_hint', '—')}…")
        mode = "dry-run (no iptables rules are installed)" if data.get("dry_run") else \
            "live (iptables + ip6tables)"
        self.mode_row.set_text(f"mode {mode}")
        self._render_info()
        self.token_row.set_text(f"API token {data.get('token_hint', '—')}… "
                                f"(stored in ~/.config/rethinkd/token)")

    def _on_theme(self, *_a) -> None:
        if self.theme_sync:
            return
        scheme = (Adw.ColorScheme.PREFER_LIGHT, Adw.ColorScheme.FORCE_LIGHT,
                  Adw.ColorScheme.FORCE_DARK)[int(self.theme.get_selected() or 0)]
        Adw.StyleManager.get_default().set_color_scheme(scheme)
        theme = ("light", "light", "dark")[int(self.theme.get_selected() or 0)]
        self.post("/api/settings", {"theme": theme}, err=lambda e: self.win.toast(e))

    def _on_start_protected(self, switch, _prop) -> None:
        if self.start_sync:
            return
        target = switch.get_active()
        self.post("/api/settings", {"start_protected": target},
                  ok=lambda _d: self.win.toast("Start protected: " + ("on" if target else "off")),
                  err=lambda e: (self.win.toast(e), setattr(self, "start_sync", True),
                                 switch.set_active(not target),
                                 setattr(self, "start_sync", False)))

    def _on_log_level(self, *_a) -> None:
        if self.log_sync:
            return
        level = ("debug", "info", "warn")[int(self.log_level.get_selected() or 1)]
        self.post("/api/settings", {"log_level": level},
                  ok=lambda _d: self.win.toast(f"Log level: {level}"))


# --------------------------------------------------------------------------- #
# window
# --------------------------------------------------------------------------- #
class RethinkWindow(Adw.ApplicationWindow):
    def __init__(self, application) -> None:
        super().__init__(application=application, title="Rethink Root",
                         default_width=1280, default_height=820)
        self.status: dict = {}
        self.current = "home"
        self.syncing = False
        self._code_nav = False

        self.pages: dict[str, Page] = {}

        overlay = Adw.ToastOverlay()
        self.overlay = overlay
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        overlay.set_child(outer)

        self.banner = Adw.Banner(title="Daemon not reachable — retrying…")
        self.banner.set_button_label("Retry")
        self.banner.connect("button-clicked", lambda *_: self.poll(force=True))
        self.banner.set_revealed(False)
        outer.append(self.banner)

        panes = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        outer.append(panes)

        # sidebar ----------------------------------------------------------
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar.set_size_request(216, -1)
        side_head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        side_head.set_margin_top(14)
        side_head.set_margin_bottom(8)
        side_head.set_margin_start(14)
        side_head.set_margin_end(14)
        brand = label("RETHINK ROOT", ("rt-brand", "rt-head"))
        side_head.append(brand)
        self.side_status = label("connecting…", ("rt-sub",))
        side_head.append(self.side_status)
        sidebar.append(side_head)

        self.nav = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.nav.add_css_class("rt-nav")
        self.nav.connect("row-selected", self._on_nav)
        nav_scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        nav_scroll.set_child(self.nav)
        nav_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        sidebar.append(nav_scroll)

        self.side_foot = label("", ("rt-sub",))
        self.side_foot.set_margin_top(8)
        self.side_foot.set_margin_bottom(12)
        self.side_foot.set_margin_start(14)
        self.side_foot.set_margin_end(14)
        self.side_foot.set_wrap(True)
        sidebar.append(self.side_foot)
        panes.append(sidebar)
        panes.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))

        # content ----------------------------------------------------------
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content.set_hexpand(True)
        header = Adw.HeaderBar()
        header.set_title_widget(Adw.WindowTitle.new("Rethink Root", "system firewall"))
        self.title_widget = header.get_title_widget()
        self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic",
                                      tooltip_text="Refresh (Ctrl+R)")
        self.refresh_btn.connect("clicked", lambda *_: self.refresh_all())
        header.pack_end(self.refresh_btn)
        menu = Gio.Menu()
        menu.append("Open web UI", "win.web")
        menu.append("Copy web UI URL", "win.copy-url")
        menu.append("Firewall page", "win.go-firewall")
        menu.append("About", "win.go-settings")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        header.pack_end(menu_btn)
        content.append(header)

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE,
                               transition_duration=140)
        self.stack.set_vexpand(True)
        content.append(self.stack)
        panes.append(content)

        self.set_content(overlay)
        self.maximize()
        self._install_actions()
        self._build_pages(self.nav)
        self._install_keys()

        self._poll_src = GLib.timeout_add_seconds(POLL_SECONDS, lambda: self.poll() or True)

    # -- construction ------------------------------------------------------
    def _build_pages(self, nav: Gtk.ListBox) -> None:
        order = {
            "home": HomePage,
            "firewall": FirewallPage,
            "dns": DnsPage,
            "logs": LogsPage,
            "stats": StatsPage,
            "proxy": ProxyPage,
            "settings": SettingsPage,
        }
        for name in PAGE_ORDER:
            page_cls = order[name]
            page = page_cls(self)
            self.pages[name] = page
            self.stack.add_named(page.widget, name)
            row = Gtk.ListBoxRow()
            box = Gtk.Box(spacing=10)
            box.set_margin_top(2)
            box.set_margin_bottom(2)
            box.set_margin_start(6)
            box.set_margin_end(6)
            image = Gtk.Image.new_from_icon_name(page_cls.icon)
            image.set_valign(Gtk.Align.CENTER)
            box.append(image)
            texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            title = label(page_cls.title, ("rt-nav-label",))
            title.set_ellipsize(Pango.EllipsizeMode.END)
            texts.append(title)
            count = label("", ("rt-nav-count",))
            count.set_ellipsize(Pango.EllipsizeMode.END)
            box.append(texts)
            texts.append(count)
            row.set_child(box)
            row.page_name = name
            row.count_label = count
            nav.append(row)
        self._code_nav = True
        nav.select_row(nav.get_row_at_index(0))
        GLib.idle_add(self._clear_code_nav)

    def _install_actions(self) -> None:
        for name, handler in (
            ("web", lambda *_: self.open_web_ui()),
            ("copy-url", lambda *_: self.copy_ui_url()),
            ("go-firewall", lambda *_: self.navigate("firewall")),
            ("go-settings", lambda *_: self.navigate("settings")),
            ("refresh", lambda *_: self.refresh_all()),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)

    def _install_keys(self) -> None:
        controller = Gtk.EventControllerKey()

        def on_key(_ctrl, keyval, _keycode, state):
            ctrl = bool(state & Gtk.accelerator_get_default_mod_mask() & Gtk.ModifierType.CONTROL_MASK)
            if ctrl and keyval in (ord("r"), ord("R")):
                self.refresh_all()
                return True
            if ctrl and keyval in (ord("f"), ord("F")):
                page = self.pages.get(self.current)
                if isinstance(page, FirewallPage):
                    page.search.grab_focus()
                    return True
                return False
            if ctrl and ord("1") <= keyval <= ord("7"):
                idx = keyval - ord("1")
                if idx < len(PAGE_ORDER):
                    self.navigate(PAGE_ORDER[idx])
                    return True
            if keyval in (Gtk.KEY_F5,):
                self.refresh_all()
                return True
            return False

        controller.connect("key-pressed", on_key)
        self.add_controller(controller)

    # -- navigation --------------------------------------------------------
    def _on_nav(self, _listbox, row) -> None:
        if row is None:
            return
        if self._code_nav:
            self._code_nav = False
            return
        name = getattr(row, "page_name", None)
        if name and name != self.current:
            self.navigate(name, from_nav=True)

    def _select_nav_row(self, name: str) -> None:
        idx = PAGE_ORDER.index(name) if name in PAGE_ORDER else -1
        row = self.nav.get_row_at_index(idx) if idx >= 0 else None
        if row is None or self.nav.get_selected_row() is row:
            return
        self._code_nav = True
        self.nav.select_row(row)
        GLib.idle_add(self._clear_code_nav)

    def _clear_code_nav(self) -> bool:
        self._code_nav = False
        return False

    def navigate(self, name: str, from_nav: bool = False) -> None:
        if name not in self.pages:
            return
        self.current = name
        self.stack.set_visible_child_name(name)
        self._select_nav_row(name)
        page = self.pages[name]
        page.load()
        self.paint_header()

    def current_page(self) -> str:
        return self.current

    def refresh_all(self) -> None:
        self.poll(force=True)
        page = self.pages.get(self.current)
        if page is not None:
            page.refresh()

    # -- api ---------------------------------------------------------------
    def api(self, method: str, path: str, payload=None, ok=None, err=None,
            timeout: float = 60.0) -> None:
        api(method, path, payload, ok=ok, err=err or self.toast, timeout=timeout)

    def toast(self, message: str) -> None:
        self.overlay.add_toast(Adw.Toast(title=esc(str(message)[:160]), timeout=4))

    def open_web_ui(self) -> None:
        url = ui_url()
        if not url:
            self.toast("Web UI URL unavailable")
            return
        Gtk.show_uri(self, url, 0)
        self.toast("Opened the web UI")

    def copy_ui_url(self) -> None:
        url = ui_url()
        if url:
            self.get_clipboard().set_text(url)
            self.toast("URL copied")

    # -- status ------------------------------------------------------------
    def poll(self, force: bool = False) -> bool:
        if self.syncing and not force:
            return True
        self.syncing = True
        api("GET", "/api/status", None, ok=self._status_ok, err=self._status_err, timeout=5.0)
        return True

    def _status_ok(self, data: dict) -> None:
        self.syncing = False
        self.status = data
        self.banner.set_revealed(False)
        self.paint_header()
        home = self.pages.get("home")
        if isinstance(home, HomePage):
            home._paint_status()
        if isinstance(self.pages.get(self.current), Page):
            page = self.pages[self.current]
            if getattr(page, "auto_refresh", False):
                page.load()

    def _status_err(self, message: str) -> None:
        self.syncing = False
        self.banner.set_title(esc(f"Daemon not reachable — {message[:90]}"))
        self.banner.set_revealed(True)
        self.side_status.set_text("daemon offline")
        self.side_status.add_css_class("bad")

    def paint_header(self) -> None:
        st = self.status or {}
        protected = bool(st.get("protected"))
        dns = st.get("dns") or {}
        status_text = "PROTECTED" if protected else "STOPPED"
        subtitle = f"{status_text} · {fmt_num(dns.get('queries', 0))} queries"
        if st.get("version"):
            subtitle += f" · v{st['version']}"
        self.title_widget.set_subtitle(subtitle)
        self.side_status.set_text(f"{status_text.lower()} · {fmt_duration(st.get('uptime_s'))}")
        for cls in ("bad", "ok"):
            self.side_status.remove_css_class(cls)
        self.side_status.add_css_class("ok" if protected else "bad")
        self.side_foot.set_text(
            f"v{st.get('version', '—')} · {st.get('running_as', '')}"
            f"{' · dry-run' if (self.pages.get('settings') and getattr(self.pages['settings'], 'data', {}) or {}).get('dry_run') else ''}")

        # sidebar counters
        fw = st.get("firewall") or {}
        proxy = st.get("proxy") or {}
        counts = {
            "firewall": f"{fmt_num(fw.get('apps_blocked', 0))} blocked",
            "proxy": "active" if proxy.get("enabled") else "off",
            "dns": f"{fmt_num(dns.get('blocked', 0))} blocked",
        }
        for i, name in enumerate(PAGE_ORDER):
            row = self.nav.get_row_at_index(i)
            if row is None:
                continue
            lbl = row.count_label
            text = counts.get(name, "")
            lbl.set_text(text)


# --------------------------------------------------------------------------- #
# application
# --------------------------------------------------------------------------- #
_CSS_PROVIDER: Gtk.CssProvider | None = None


def install_css() -> None:
    """Apply the app stylesheet once a display exists."""
    global _CSS_PROVIDER
    display = Gdk.Display.get_default()
    if display is None or _CSS_PROVIDER is not None:
        return
    provider = Gtk.CssProvider()
    provider.load_from_data(CSS.encode("utf-8"))
    Gtk.StyleContext.add_provider_for_display(
        display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _CSS_PROVIDER = provider


class RethinkApp(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.window: RethinkWindow | None = None
        self.connect("activate", self._activate)

    def _activate(self, _app) -> None:
        install_css()
        if self.window is None:
            self.window = RethinkWindow(application=self)
            self.window.poll(force=True)
            page = os.environ.get("RETHINK_APP_PAGE") or "home"
            self.window.navigate(page if page in self.window.pages else "home", from_nav=True)
        self.window.present()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    selftest = None
    cleaned: list[str] = []
    skip_next = False
    for i, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg == "--selftest":
            selftest = 5
            if i + 1 < len(argv) and argv[i + 1].isdigit():
                skip_next = True
                selftest = int(argv[i + 1])
        elif arg.startswith("--selftest="):
            try:
                selftest = int(arg.split("=", 1)[1]) or 5
            except ValueError:
                selftest = 5
        else:
            cleaned.append(arg)
    if selftest is not None:
        argv = cleaned
    env_selftest = os.environ.get("RETHINK_APP_SELFTEST")
    if env_selftest and selftest is None:
        try:
            selftest = int(env_selftest)
        except ValueError:
            selftest = 5

    # GLib must not warn about stray arguments passed to Gtk.Application
    sys.argv = [argv[0]] + [a for a in argv[1:] if not a.isdigit()]

    app = RethinkApp()
    if selftest:
        def start_probes() -> bool:
            win = app.window
            if win:
                for name in PAGE_ORDER:
                    page = win.pages.get(name)
                    if page is not None:
                        page.load()
                logs = win.pages.get("logs")
                if logs is not None and getattr(logs, "stack", None) is not None:
                    logs.stack.set_visible_child_name("activity")
                    logs.stack.set_visible_child_name("dns")
            return False

        def quit_later() -> bool:
            win = app.window
            status = (win.status if win else {}) or {}
            parts = [
                f"connected={'version' in status}",
                f"version={status.get('version', '?')}",
                f"protected={status.get('protected', '?')}",
                f"pages={','.join(sorted(win.pages)) if win else ''}",
            ]
            errors = 0
            if win:
                fw = win.pages["firewall"]
                dns = win.pages["dns"]
                logs = win.pages["logs"]
                stats = win.pages["stats"]
                proxy = win.pages["proxy"]
                settings = win.pages["settings"]
                home = win.pages["home"]
                for page in (fw, dns, logs, stats, proxy, settings, home):
                    if page.error:
                        errors += 1
                parts += [
                    f"apps={len(getattr(fw, 'apps', []))}",
                    f"policy={getattr(fw, 'policy', '?')}",
                    f"cats={len((getattr(dns, 'data_lists', {}) or {}).get('categories', []))}",
                    f"domains={len((dns.data or {}).get('block', []))}",
                    f"log={len((logs.data or {}).get('log', []))}",
                    f"events={len(logs.activity if hasattr(logs, 'activity') else [])}",
                    f"series={len(stats.series)}",
                    f"top={len(stats.top_blocked)}",
                    f"proxy={bool((proxy.data or {}).get('enabled'))}",
                    f"settings={(settings.data or {}).get('version', '?')}",
                    f"errors={errors}",
                ]
            print("rethink-selftest:", " ".join(parts), flush=True)
            app.quit()
            return False

        GLib.timeout_add_seconds(max(1, selftest - 3), start_probes)
        GLib.timeout_add_seconds(max(3, selftest), quit_later)
    return app.run(argv)
