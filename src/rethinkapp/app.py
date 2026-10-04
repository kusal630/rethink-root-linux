"""Rethink Root native desktop app for COSMIC / GTK4 + libadwaita.

Talks to the local rethinkd daemon over the same authenticated API the web UI
uses, so every feature is available: protection switch, per-app firewall,
DNS rules and log, blocklists, proxy and settings.
"""

from __future__ import annotations

import os
import sys
import threading

try:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
except (ImportError, ValueError) as exc:  # pragma: no cover - packaging fallback
    raise SystemExit(
        "rethink-app needs python3-gi, gir1.2-gtk-4.0 and gir1.2-adw-1 "
        f"(sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1): {exc}"
    ) from exc

from gi.repository import Adw, Gio, GLib, Gtk, Pango  # noqa: E402

from rethinkd.client import ApiError, call  # noqa: E402

POLICIES = ("allow", "block")
UPSTREAMS = ("system", "plain", "doh", "dot")
PROXY_TYPES = ("http", "socks5")

ICONS = {
    "home": "security-high",
    "apps": "applications-system",
    "dns": "network-workgroup",
    "lists": "filter",
    "proxy": "network-transmit-receive",
    "settings": "preferences-system",
}


def fmt_num(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


# --------------------------------------------------------------------------- #
# pages
# --------------------------------------------------------------------------- #
def esc(value) -> str:
    return GLib.markup_escape_text(str(value))


def group_add(group: Adw.PreferencesGroup, widget, owned: dict) -> None:
    group.add(widget)
    owned.setdefault(group, []).append(widget)


def group_clear(group: Adw.PreferencesGroup, owned: dict) -> None:
    for widget in owned.pop(group, []):
        group.remove(widget)


class Page:
    """Base class: a titled page inside the view stack."""

    title = ""

    def __init__(self, window: "RethinkWindow") -> None:
        self.win = window
        self.widget = self.build()

    def build(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def refresh(self) -> None:  # pragma: no cover - overridden
        pass


class DashboardPage(Page):
    title = "Dashboard"

    def build(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        self.banner = Adw.Banner(title="Daemon not reachable — retrying…")
        self.banner.set_button_label("Retry")
        self.banner.connect("button-clicked", lambda *_: self.win.poll(force=True))
        self.banner.set_revealed(False)
        outer.append(self.banner)

        scrolled = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, margin_top=18,
                          margin_bottom=24, margin_start=24, margin_end=24)
        scrolled.set_child(content)
        outer.append(scrolled)

        # --- protection card ---
        protect = Adw.PreferencesGroup()
        self.protect_row = Adw.SwitchRow(title="Protection", subtitle="Block trackers, ads and unwanted apps system-wide")
        self.protect_row.connect("notify::active", self._on_protect)
        protect.add(self.protect_row)
        content.append(protect)

        # --- live numbers ---
        stats = Adw.PreferencesGroup()
        self.rows = {}
        for key, title in (
            ("queries", "DNS queries"),
            ("blocked", "Blocked"),
            ("rate", "Block rate"),
            ("dropped", "Firewall drops"),
        ):
            row = Adw.ActionRow(title=title)
            label = Gtk.Label(label="—", xalign=1)
            label.add_css_class("title-1")
            row.add_suffix(label)
            stats.add(row)
            self.rows[key] = label
        content.append(stats)

        # --- health ---
        health = Adw.PreferencesGroup()
        self.health = {}
        for key, title in (
            ("dns", "DNS"),
            ("firewall", "Firewall"),
            ("proxy", "Proxy"),
            ("host", "Host"),
        ):
            row = Adw.ActionRow(title=title)
            label = Gtk.Label(label="—", xalign=1, ellipsize=Pango.EllipsizeMode.END)
            label.add_css_class("dim-label")
            row.add_suffix(label)
            health.add(row)
            self.health[key] = label
        content.append(health)

        # --- recent activity ---
        activity_group = Adw.PreferencesGroup(title="Recent activity")
        self.activity = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.activity.add_css_class("boxed-list")
        group_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        note = Gtk.Label(label="Live feed of DNS and firewall decisions", xalign=0)
        note.add_css_class("dim-label")
        group_box.append(note)
        group_box.append(self.activity)
        activity_group.add(group_box)
        content.append(activity_group)
        return outer

    def _on_protect(self, *_a) -> None:
        if self.win.syncing:
            return
        wanted = self.protect_row.get_active()
        self.win.api("POST", "/api/protected", {"on": wanted},
                     ok=lambda _r: self.win.poll(force=True),
                     err=lambda e: self.win.toast(e))

    def update(self, status: dict) -> None:
        self.win.syncing = True
        self.protect_row.set_active(bool(status.get("protected")))
        self.win.syncing = False
        dns = status.get("dns", {})
        fw = status.get("firewall", {})
        proxy = status.get("proxy", {})
        host = status.get("host", {})
        self.rows["queries"].set_text(fmt_num(dns.get("queries", 0)))
        self.rows["blocked"].set_text(fmt_num(dns.get("blocked", 0)))
        self.rows["rate"].set_text(f"{dns.get('block_rate', 0)}%")
        self.rows["dropped"].set_text(fmt_num(fw.get("dropped_packets", 0)))

        self.health["dns"].set_text(
            f"{len(dns.get('listening', []) or [])} listener(s) · upstream {dns.get('upstream', '?')}"
        )
        if fw.get("error"):
            self.health["firewall"].set_text("error: " + str(fw["error"])[:80])
            self.health["firewall"].add_css_class("error")
        else:
            self.health["firewall"].set_text(
                "active" if fw.get("enabled") else ("dry-run" if fw.get("dry_run") else "inactive")
            )
            self.health["firewall"].remove_css_class("error")
        self.health["proxy"].set_text(
            f"on · {proxy.get('endpoint')}" if proxy.get("enabled") else "off"
        )
        self.health["host"].set_text(
            f"{host.get('os', '?')} · uid {host.get('uid', '?')} · {status.get('running_as', '')}"
        )

    def set_activity(self, events: list) -> None:
        while (child := self.activity.get_first_child()) is not None:
            self.activity.remove(child)
        if not events:
            placeholder = Gtk.Label(label="No activity yet", margin_top=8, margin_bottom=8)
            placeholder.add_css_class("dim-label")
            holder = Gtk.Box()
            holder.append(placeholder)
            row = Gtk.ListBoxRow(activatable=False, selectable=False)
            row.set_child(holder)
            self.activity.append(row)
            return
        for event in events[:25]:
            action = str(event.get("action") or "")
            blocked = action in ("blocked", "drop")
            dot = Gtk.Label(label="●")
            dot.add_css_class("error" if blocked else "success")
            box = Gtk.Box(spacing=10, margin_top=6, margin_bottom=6, margin_start=10, margin_end=10)
            box.append(dot)
            text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            main = Gtk.Label(label=str(event.get("name") or ""), xalign=0)
            main.add_css_class("heading")
            sub = Gtk.Label(
                label=f"{event.get('kind', '')} · {action} · {event.get('reason') or '—'}", xalign=0
            )
            sub.add_css_class("dim-label")
            sub.add_css_class("caption")
            text.append(main)
            text.append(sub)
            box.append(text)
            row = Gtk.ListBoxRow(activatable=False, selectable=False)
            row.set_child(box)
            self.activity.append(row)


class AppsPage(Page):
    title = "Apps"

    def build(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        top = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12,
                      margin_bottom=6, margin_start=12, margin_end=12)
        self.search = Gtk.SearchEntry(placeholder_text="Search apps")
        self.search.connect("notify::text", lambda *_: self.render())
        top.append(self.search)

        bar = Gtk.Box(spacing=12)
        self.policy = Adw.ComboRow(title="Default policy", model=Gtk.StringList.new(list(POLICIES)))
        self.policy.connect("notify::selected", self._on_policy)
        self.policy.set_size_request(260, -1)
        bar.append(self.policy)
        refresh = Gtk.Button(label="Refresh", valign=Gtk.Align.CENTER)
        refresh.connect("clicked", lambda *_: self.load())
        bar.append(refresh)
        top.append(bar)
        outer.append(top)

        scrolled = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.listbox.add_css_class("boxed-list")
        holder = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0, margin_start=12,
                         margin_end=12, margin_bottom=18)
        holder.append(self.listbox)
        scrolled.set_child(holder)
        outer.append(scrolled)
        self.apps: list[dict] = []
        self.policy_sync = False
        return outer

    def _on_policy(self, *_a) -> None:
        if self.policy_sync:
            return
        wanted = POLICIES[self.policy.get_selected()]
        self.win.api("POST", "/api/policy", {"policy": wanted},
                     ok=lambda _r: self.load(), err=lambda e: self.win.toast(e))

    def load(self) -> None:
        self.win.api("GET", "/api/apps", ok=self._loaded, err=lambda e: self.win.toast(e))

    def _loaded(self, data: dict) -> None:
        self.apps = list(data.get("apps") or [])
        self.policy_sync = True
        self.policy.set_selected(POLICIES.index(data.get("policy", "allow")) if data.get("policy") in POLICIES else 0)
        self.policy_sync = False
        self.render()

    def render(self) -> None:
        while (child := self.listbox.get_first_child()) is not None:
            self.listbox.remove(child)
        needle = self.search.get_text().strip().lower()
        shown = 0
        for app in self.apps:
            name = str(app.get("name") or f"uid {app.get('uid')}")
            exe = str(app.get("exe") or "")
            if needle and needle not in name.lower() and needle not in exe.lower():
                continue
            shown += 1
            action = str(app.get("action") or "allow")
            blocked = action == "block"
            row = Adw.ActionRow(title=esc(name),
                               subtitle=esc(f"uid {app.get('uid')} · {exe or '—'} · {app.get('conns', 0)} conn"))
            switch = Gtk.Switch(valign=Gtk.Align.CENTER, active=blocked)
            switch.connect("notify::active", self._on_switch, app)
            row.add_suffix(switch)
            if app.get("explicit"):
                badge = Gtk.Label(label="explicit")
                badge.add_css_class("accent")
                badge.add_css_class("caption")
                row.add_suffix(badge)
            self.listbox.append(row)
        if not shown:
            empty = Gtk.Label(label="No matching apps", margin_top=24, margin_bottom=24)
            empty.add_css_class("dim-label")
            box = Gtk.Box()
            box.append(empty)
            row = Gtk.ListBoxRow(activatable=False, selectable=False)
            row.set_child(box)
            self.listbox.append(row)

    def _on_switch(self, switch, _prop, app: dict) -> None:
        if switch.get_active() == (str(app.get("action")) == "block"):
            return
        action = "block" if switch.get_active() else "allow"
        uid = int(app.get("uid"))
        self.win.api(
            "POST", "/api/apps", {"uid": uid, "action": action},
            ok=lambda _r: self.load(),
            err=lambda e: (self.win.toast(e), switch.set_active(not switch.get_active())),
        )


class DnsPage(Page):
    title = "DNS"

    def build(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolled = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, margin_top=12,
                          margin_bottom=24, margin_start=12, margin_end=12)
        scrolled.set_child(content)
        outer.append(scrolled)

        upstream_group = Adw.PreferencesGroup(title="Upstream resolver")
        self.upstream = Adw.ComboRow(title="Type", model=Gtk.StringList.new(list(UPSTREAMS)))
        self.url = Adw.EntryRow(title="Endpoint (plain / tls://host / https://host/dns-query)")
        apply_row = Gtk.Box(spacing=12)
        apply_btn = Gtk.Button(label="Apply upstream", valign=Gtk.Align.CENTER)
        apply_btn.add_css_class("suggested-action")
        apply_btn.connect("clicked", lambda *_: self.apply_upstream())
        apply_row.append(apply_btn)
        upstream_group.add(self.upstream)
        upstream_group.add(self.url)
        content.append(upstream_group)
        content.append(apply_row)

        hijack_group = Adw.PreferencesGroup(title="System-wide hijack")
        self.hijack = Adw.SwitchRow(title="Redirect every port-53 query to Rethink Root")
        self.hijack.connect("notify::active", self._on_hijack)
        hijack_group.add(self.hijack)
        content.append(hijack_group)

        rules_group = Adw.PreferencesGroup(title="Domain overrides")
        self.domain = Adw.EntryRow(title="Domain")
        buttons = Gtk.Box(spacing=12)
        for label, action in (("Block", "block"), ("Allow", "allow"), ("Remove", "remove")):
            btn = Gtk.Button(label=label)
            btn.connect("clicked", lambda _b, a=action: self.domain_action(a))
            buttons.append(btn)
        rules_group.add(self.domain)
        content.append(rules_group)
        content.append(buttons)

        log_group = Adw.PreferencesGroup(title="Query log")
        head = Gtk.Box(spacing=12)
        clear = Gtk.Button(label="Clear log")
        clear.connect("clicked", lambda *_: self.win.api("POST", "/api/dns/clearlog", {},
                                                         ok=lambda _r: self.load(), err=lambda e: self.win.toast(e)))
        head.append(clear)
        log_group.add(head)
        self.logbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.logbox.add_css_class("boxed-list")
        log_group.add(self.logbox)
        content.append(log_group)

        self.hijack_sync = False
        self.data: dict = {}
        return outer

    def _on_hijack(self, *_a) -> None:
        if self.hijack_sync:
            return
        wanted = self.hijack.get_active()
        self.win.api("POST", "/api/dns/hijack", {"enabled": wanted},
                     ok=lambda _r: self.load(), err=lambda e: self.win.toast(e))

    def apply_upstream(self) -> None:
        kind = UPSTREAMS[self.upstream.get_selected()]
        payload = {"type": kind, "url": self.url.get_text().strip()}
        self.win.api("POST", "/api/dns/upstream", payload,
                     ok=lambda _r: (self.win.toast("Upstream updated"), self.load()),
                     err=lambda e: self.win.toast(e))

    def domain_action(self, action: str) -> None:
        domain = self.domain.get_text().strip()
        if not domain:
            self.win.toast("Enter a domain first")
            return
        if action == "remove":
            self.win.api("DELETE", f"/api/dns/domain/{domain}",
                         ok=lambda _r: (self.domain.set_text(""), self.load()), err=lambda e: self.win.toast(e))
        else:
            self.win.api("POST", "/api/dns/domain", {"domain": domain, "action": action},
                         ok=lambda _r: (self.domain.set_text(""), self.load()), err=lambda e: self.win.toast(e))

    def load(self) -> None:
        self.win.api("GET", "/api/dns", ok=self._loaded, err=lambda e: self.win.toast(e))

    def _loaded(self, data: dict) -> None:
        self.data = data
        upstream = data.get("upstream") or {}
        kind = str(upstream.get("type") or "system")
        if kind in UPSTREAMS:
            self.upstream.set_selected(UPSTREAMS.index(kind))
        self.url.set_text(str(upstream.get("url") or ""))
        self.hijack_sync = True
        self.hijack.set_active(bool(data.get("hijack")))
        self.hijack_sync = False

        while (child := self.logbox.get_first_child()) is not None:
            self.logbox.remove(child)
        entries = list(data.get("log") or [])[:40]
        if not entries:
            row = Gtk.ListBoxRow(activatable=False, selectable=False)
            label = Gtk.Label(label="No queries yet", margin_top=10, margin_bottom=10)
            label.add_css_class("dim-label")
            box = Gtk.Box()
            box.append(label)
            row.set_child(box)
            self.logbox.append(row)
        for entry in entries:
            blocked = bool(entry.get("blocked"))
            dot = Gtk.Label(label="●")
            dot.add_css_class("error" if blocked else "success")
            box = Gtk.Box(spacing=10, margin_top=6, margin_bottom=6, margin_start=10, margin_end=10)
            box.append(dot)
            text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            main = Gtk.Label(label=str(entry.get("name") or ""), xalign=0)
            main.add_css_class("heading")
            sub = Gtk.Label(
                label=f"{entry.get('type')} · {'blocked' if blocked else 'allowed'}"
                      f"{' · ' + str(entry.get('reason')) if entry.get('reason') else ''}",
                xalign=0,
            )
            sub.add_css_class("dim-label")
            sub.add_css_class("caption")
            text.append(main)
            text.append(sub)
            box.append(text)
            row = Gtk.ListBoxRow(activatable=False, selectable=False)
            row.set_child(box)
            self.logbox.append(row)


class ListsPage(Page):
    title = "Lists"

    def build(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolled = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, margin_top=12,
                          margin_bottom=24, margin_start=12, margin_end=12)
        scrolled.set_child(content)
        outer.append(scrolled)

        head = Gtk.Box(spacing=12)
        self.spinner = Gtk.Spinner()
        self.refresh_btn = Gtk.Button(label="Refresh all lists")
        self.refresh_btn.connect("clicked", lambda *_: self.refresh_all())
        head.append(self.refresh_btn)
        head.append(self.spinner)
        content.append(head)

        self.builtin_group = Adw.PreferencesGroup(title="Built-in categories")
        content.append(self.builtin_group)
        self.custom_group = Adw.PreferencesGroup(title="Custom lists")
        content.append(self.custom_group)
        self._owned: dict = {}

        add_box = Gtk.Box(spacing=12)
        self.custom_url = Adw.EntryRow(title="https://example.com/list.txt")
        add_btn = Gtk.Button(label="Add list", valign=Gtk.Align.CENTER)
        add_btn.connect("clicked", lambda *_: self.add_custom())
        add_box.append(self.custom_url)
        add_box.append(add_btn)
        content.append(add_box)
        return outer

    def load(self) -> None:
        self.win.api("GET", "/api/blocklists", ok=self._loaded, err=lambda e: self.win.toast(e))

    def _loaded(self, data: dict) -> None:
        self.data = dict(data)
        group_clear(self.builtin_group, self._owned)
        for cat in data.get("categories") or []:
            subtitle = f"{fmt_num(cat.get('domains', 0))} domains"
            if cat.get("last_error"):
                subtitle += f" · error: {str(cat['last_error'])[:60]}"
            row = Adw.SwitchRow(title=esc(cat.get("name") or cat.get("id")), subtitle=esc(subtitle))
            row.set_active(bool(cat.get("enabled")))
            row.connect("notify::active", self._on_toggle, str(cat.get("id")))
            group_add(self.builtin_group, row, self._owned)
        group_clear(self.custom_group, self._owned)
        custom = data.get("custom") or []
        if not custom:
            label = Gtk.Label(label="No custom lists", xalign=0)
            label.add_css_class("dim-label")
            group_add(self.custom_group, label, self._owned)
        for entry in custom:
            subtitle = f"{fmt_num(entry.get('domains', 0))} domains · {entry.get('url')}"
            if entry.get("last_error"):
                subtitle += f" · error: {str(entry['last_error'])[:60]}"
            row = Adw.ActionRow(title=esc(entry.get("url")), subtitle=esc(subtitle))
            switch = Gtk.Switch(valign=Gtk.Align.CENTER, active=bool(entry.get("enabled")))
            switch.connect("notify::active", self._on_toggle, str(entry.get("id")))
            row.add_suffix(switch)
            remove = Gtk.Button(icon_name="user-trash", valign=Gtk.Align.CENTER)
            remove.connect("clicked", lambda _b, cid=str(entry.get("id")): self.remove_custom(cid))
            row.add_suffix(remove)
            group_add(self.custom_group, row, self._owned)

    def _on_toggle(self, row, _prop, item_id: str) -> None:
        self.win.api("POST", "/api/blocklists", {"id": item_id, "enabled": row.get_active()},
                     ok=lambda _r: self.load(), err=lambda e: self.win.toast(e))

    def add_custom(self) -> None:
        url = self.custom_url.get_text().strip()
        if not url.startswith(("http://", "https://")):
            self.win.toast("Enter an http(s) URL")
            return
        self.win.api("POST", "/api/blocklists/custom", {"url": url, "enabled": True},
                     ok=lambda _r: (self.custom_url.set_text(""), self.load()), err=lambda e: self.win.toast(e))

    def remove_custom(self, cid: str) -> None:
        self.win.api("DELETE", f"/api/blocklists/custom/{cid}",
                     ok=lambda _r: self.load(), err=lambda e: self.win.toast(e))

    def refresh_all(self) -> None:
        self.refresh_btn.set_sensitive(False)
        self.spinner.start()

        def done(data):
            self.spinner.stop()
            self.refresh_btn.set_sensitive(True)
            self.win.toast(f"Refreshed {data.get('categories', 0)} lists · {fmt_num(data.get('domains', 0))} domains")
            self.load()

        def failed(error: str):
            self.spinner.stop()
            self.refresh_btn.set_sensitive(True)
            self.win.toast(error)

        self.win.api("POST", "/api/blocklists/refresh", {}, ok=done, err=failed, timeout=300)


class ProxyPage(Page):
    title = "Proxy"

    def build(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolled = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, margin_top=12,
                          margin_bottom=24, margin_start=12, margin_end=12)
        scrolled.set_child(content)
        outer.append(scrolled)

        group = Adw.PreferencesGroup(title="Outbound proxy", description="Redirects outbound TCP through your own exit node")
        self.type = Adw.ComboRow(title="Protocol", model=Gtk.StringList.new(list(PROXY_TYPES)))
        self.host = Adw.EntryRow(title="Host")
        self.port = Adw.SpinRow.new_with_range(0, 65535, 1)
        self.port.set_title("Port")
        self.user = Adw.EntryRow(title="Username (optional)")
        self.password = Adw.PasswordEntryRow(title="Password (optional)")
        self.bypass = Adw.SwitchRow(title="Bypass LAN and loopback", subtitle="Keep local traffic off the proxy")
        self.enabled = Adw.SwitchRow(title="Use this proxy")
        for widget in (self.type, self.host, self.port, self.user, self.password, self.bypass, self.enabled):
            group.add(widget)
        content.append(group)

        actions = Gtk.Box(spacing=12)
        save = Gtk.Button(label="Save proxy settings")
        save.add_css_class("suggested-action")
        save.connect("clicked", lambda *_: self.save())
        actions.append(save)
        content.append(actions)

        status_group = Adw.PreferencesGroup(title="Status")
        self.status_row = Adw.ActionRow(title="State", subtitle="—")
        status_group.add(self.status_row)
        content.append(status_group)
        self.enabled_sync = False
        return outer

    def load(self) -> None:
        self.win.api("GET", "/api/proxy", ok=self._loaded, err=lambda e: self.win.toast(e))

    def _loaded(self, data: dict) -> None:
        self.data = dict(data)
        kinds = list(PROXY_TYPES)
        kind = str(data.get("type") or "http")
        self.type.set_selected(kinds.index(kind) if kind in kinds else 0)
        self.host.set_text(str(data.get("host") or ""))
        self.port.set_value(int(data.get("port") or 0))
        self.user.set_text(str(data.get("username") or ""))
        self.password.set_text(str(data.get("password") or ""))
        self.bypass.set_active(bool(data.get("bypass_lan")))
        self.enabled_sync = True
        self.enabled.set_active(bool(data.get("enabled")))
        self.enabled_sync = False
        state = "on → " + str(data.get("endpoint")) if data.get("enabled") else "off"
        extra = f" · {fmt_num(data.get('relayed', 0))} relayed, {fmt_num(data.get('active', 0))} open"
        if data.get("last_error"):
            extra = " · error: " + str(data["last_error"])[:80]
        self.status_row.set_subtitle(state + extra)

    def save(self) -> None:
        payload = {
            "type": PROXY_TYPES[self.type.get_selected()],
            "host": self.host.get_text().strip(),
            "port": int(self.port.get_value()),
            "username": self.user.get_text().strip(),
            "bypass_lan": self.bypass.get_active(),
            "enabled": self.enabled.get_active(),
            "bypass_domains": [],
        }
        if self.password.get_text():
            payload["password"] = self.password.get_text()
        self.win.api("POST", "/api/proxy", payload,
                     ok=lambda _r: (self.win.toast("Proxy saved"), self.load()),
                     err=lambda e: self.win.toast(e))


class SettingsPage(Page):
    title = "Settings"

    def build(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolled = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, margin_top=12,
                          margin_bottom=24, margin_start=12, margin_end=12)
        scrolled.set_child(content)
        outer.append(scrolled)

        theme_group = Adw.PreferencesGroup(title="Appearance")
        self.theme = Adw.ComboRow(title="Theme", model=Gtk.StringList.new(["System", "Light", "Dark"]))
        self.theme.connect("notify::selected", self._on_theme)
        theme_group.add(self.theme)
        content.append(theme_group)
        self.theme_sync = False

        self.info_group = Adw.PreferencesGroup(title="About")
        content.append(self.info_group)
        self._owned = {}

        log_group = Adw.PreferencesGroup(title="Logging")
        self.log_level = Adw.ComboRow(title="Log level", model=Gtk.StringList.new(["debug", "info", "warn"]))
        log_group.add(self.log_level)
        content.append(log_group)
        return outer

    def _on_theme(self, *_a) -> None:
        if self.theme_sync:
            return
        schemes = (Adw.ColorScheme.PREFER_LIGHT, Adw.ColorScheme.FORCE_LIGHT, Adw.ColorScheme.FORCE_DARK)
        Adw.StyleManager.get_default().set_color_scheme(schemes[self.theme.get_selected()])
        self.win.api("POST", "/api/settings", {"theme": ("light", "light", "dark")[self.theme.get_selected()]},
                     ok=lambda _r: None, err=lambda e: self.win.toast(e))

    def load(self) -> None:
        self.win.api("GET", "/api/settings", ok=self._loaded, err=lambda e: self.win.toast(e))

    def _loaded(self, data: dict) -> None:
        self.data = dict(data)
        theme = str(data.get("theme") or "dark")
        self.theme_sync = True
        self.theme.set_selected(1 if theme == "light" else 2 if theme == "dark" else 0)
        self.theme_sync = False
        group_clear(self.info_group, self._owned)
        for title, value in (
            ("Version", data.get("version", "—")),
            ("Listen", data.get("listen", "—")),
            ("API token", (str(data.get("token_hint") or "—")) + "…"),
            ("Firewall mode", "dry-run (no iptables)" if data.get("dry_run") else "live"),
            ("Start protected", "yes" if data.get("start_protected") else "no"),
        ):
            row = Adw.ActionRow(title=esc(title))
            label = Gtk.Label(label=str(value), xalign=1, ellipsize=Pango.EllipsizeMode.END)
            label.add_css_class("dim-label")
            row.add_suffix(label)
            group_add(self.info_group, row, self._owned)

# --------------------------------------------------------------------------- #
# window / application
# --------------------------------------------------------------------------- #
class RethinkWindow(Adw.ApplicationWindow):
    POLL_SECONDS = 3

    def __init__(self, application) -> None:
        super().__init__(application=application, title="Rethink Root", default_width=1080, default_height=720)
        self.syncing = False
        self.status: dict = {}
        self.api_busy = False

        self.pages: dict[str, Page] = {
            "home": DashboardPage(self),
            "apps": AppsPage(self),
            "dns": DnsPage(self),
            "lists": ListsPage(self),
            "proxy": ProxyPage(self),
            "settings": SettingsPage(self),
        }

        self.stack = Adw.ViewStack(vexpand=True)
        for name, page in self.pages.items():
            self.stack.add_titled_with_icon(page.widget, name, page.title, ICONS[name])
        self.stack.connect("notify::visible-child", self._on_page)

        switcher = Adw.ViewSwitcher(stack=self.stack, policy=Adw.ViewSwitcherPolicy.WIDE, valign=Gtk.Align.CENTER)
        sidebar_scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12,
                              margin_bottom=12, margin_start=6, margin_end=6)
        sidebar_box.append(switcher)
        sidebar_scroll.set_child(sidebar_box)
        sidebar = Adw.NavigationPage(child=sidebar_scroll, title="Rethink Root")

        # header with the master protection switch
        self.header = Adw.HeaderBar()
        self.header.set_title_widget(Adw.WindowTitle.new("Rethink Root", "system firewall"))
        end_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.head_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.head_switch.connect("notify::active", self._on_head_switch)
        end_box.append(Gtk.Label(label="Protect"))
        end_box.append(self.head_switch)
        refresh = Gtk.Button(icon_name="view-refresh", valign=Gtk.Align.CENTER, tooltip_text="Refresh")
        refresh.connect("clicked", lambda *_: self.refresh_current(force=True))
        end_box.append(refresh)
        self.header.pack_end(end_box)

        self.overlay = Adw.ToastOverlay()
        page_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        page_box.append(self.header)
        page_box.append(self.stack)
        self.overlay.set_child(page_box)
        content_page = Adw.NavigationPage(child=self.overlay, title="Content")

        split = Adw.NavigationSplitView(sidebar=sidebar, content=content_page)
        split.set_min_sidebar_width(220)
        self.set_content(split)

        self.poll(force=True)
        GLib.timeout_add_seconds(self.POLL_SECONDS, lambda: self.poll() or True)

    # -- plumbing --------------------------------------------------------
    def api(self, method: str, path: str, payload=None, ok=None, err=None, timeout: float = 60.0) -> None:
        """Run an API call off the UI thread and hand the result back."""

        def worker():
            try:
                result = call(method, path, payload, timeout)
            except ApiError as exc:
                if err:
                    GLib.idle_add(lambda: (err(str(exc)), False)[1])
                else:
                    GLib.idle_add(lambda: (self.toast(str(exc)), False)[1])
                return
            if ok:
                GLib.idle_add(lambda: (ok(result), False)[1])

        threading.Thread(target=worker, daemon=True, name="api").start()

    def toast(self, message: str) -> None:
        self.overlay.add_toast(Adw.Toast(title=esc(str(message)[:160]), timeout=4))

    def _on_head_switch(self, *_a) -> None:
        if self.syncing:
            return
        wanted = self.head_switch.get_active()
        self.api("POST", "/api/protected", {"on": wanted},
                 ok=lambda _r: self.poll(force=True), err=lambda e: self.toast(e))

    def _on_page(self, *_a) -> None:
        self.refresh_current()

    def current_page(self) -> str | None:
        child = self.stack.get_visible_child()
        for name, page in self.pages.items():
            if page.widget is child:
                return name
        return None

    def refresh_current(self, force: bool = False) -> None:
        name = self.current_page()
        if not name:
            return
        page = self.pages[name]
        if name == "home":
            page.win.api("GET", "/api/activity", ok=lambda d: page.set_activity(d.get("events") or []),
                         err=lambda e: None)
            return
        if hasattr(page, "load"):
            page.load()

    def poll(self, force: bool = False) -> bool:
        if self.api_busy and not force:
            return True
        self.api_busy = True

        def done(status: dict) -> None:
            self.api_busy = False
            self.status = status
            banner = self.pages["home"].banner
            banner.set_revealed(False)
            self.syncing = True
            self.head_switch.set_active(bool(status.get("protected")))
            self.syncing = False
            self.pages["home"].update(status)
            self.refresh_current()
            self.header.set_title_widget(
                Adw.WindowTitle.new("Rethink Root", f"v{status.get('version', '?')} · {status.get('uptime_s', 0)}s")
            )

        def failed(error: str) -> None:
            self.api_busy = False
            banner = self.pages["home"].banner
            banner.set_title(esc(f"Daemon not reachable — {error[:90]}"))
            banner.set_revealed(True)

        self.api("GET", "/api/status", ok=done, err=failed, timeout=6)
        return True


class RethinkApp(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id="rs.rethinkroot.App", flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", self._activate)
        self.window: RethinkWindow | None = None

    def _activate(self, _app) -> None:
        if self.window is None:
            self.window = RethinkWindow(application=self)
        self.window.present()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    selftest = None
    cleaned: list[str] = []
    it = iter(range(len(argv)))
    for i in it:
        arg = argv[i]
        if arg == "--selftest":
            selftest = 5
            if i + 1 < len(argv) and argv[i + 1].isdigit():
                next(it)
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
    if env_selftest:
        try:
            selftest = int(env_selftest)
        except ValueError:
            selftest = 5

    app = RethinkApp()
    if selftest:
        # packaging smoke test: probe every data source, report, then quit
        def start_probes() -> bool:
            win = app.window
            if win:
                for name in ("apps", "dns", "lists", "proxy", "settings"):
                    page = win.pages[name]
                    if hasattr(page, "load"):
                        page.load()
                win.api("GET", "/api/activity",
                        ok=lambda d: setattr(win.pages["home"], "_events", d.get("events") or []))
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
            if win:
                apps = win.pages["apps"]
                dns = win.pages["dns"]
                lists = win.pages["lists"]
                proxy = win.pages["proxy"]
                settings = win.pages["settings"]
                parts += [
                    f"apps={len(apps.apps)}",
                    f"policy={apps.policy.get_selected()}",
                    f"dns_log={len((dns.data or {}).get('log', []))}",
                    f"categories={len((lists.data or {}).get('categories', []))}",
                    f"custom_lists={len((lists.data or {}).get('custom', []))}",
                    f"proxy_port={int((proxy.data or {}).get('port', 0))}",
                    f"settings_version={(settings.data or {}).get('version', '?')}",
                    f"activity={len(getattr(win.pages['home'], '_events', []) or [])}",
                ]
            print("rethink-selftest:", " ".join(parts), flush=True)
            app.quit()
            return False

        GLib.timeout_add_seconds(max(1, selftest - 2), start_probes)
        GLib.timeout_add_seconds(max(2, selftest), quit_later)
    return app.run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
