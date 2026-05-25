import sys
import random
import pandas as pd

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QDialog, QTextEdit, QLabel, QProgressBar, QMenu
)

from PyQt6.QtCore import QTimer, Qt, QPoint
import pyqtgraph as pg

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import requests
import json

# ---------------- CONFIG ----------------
CSV_FILE = "apt_events.csv"
MAX_EVENTS = 10000
VT_API_KEY = "XXXXxxXxXx"

ACTION_TYPES = [
    "login_attempt",
    "failed_login",
    "data_read",
    "data_write",
    "data_exfiltration",
    "config_change",
    "suspicious_endpoint"
]

ACTION_COLORS = {
    "login_attempt": "#8DFF91",
    "failed_login": "#FF9E9E",
    "data_read": "#7CC4FF",
    "data_write": "#FFDA6A",
    "data_exfiltration": "#FF4848",
    "config_change": "#C78CFF",
    "suspicious_endpoint": "#FF7348"
}

KILL_CHAIN_MAPPING = {
    "Recon": ["login_attempt", "data_read"],
    "Movement": ["data_write", "suspicious_endpoint"],
    "Privilege": ["config_change"],
    "Exfil": ["data_exfiltration"]
}

# -------Virus Total IP Reputation----------
class IPReputationDialog(QDialog):
    def __init__(self, ip, vt_data):
        super().__init__()
        self.setWindowTitle(f"IP Reputation - {ip}")
        layout = QVBoxLayout()

        # ---------------- IP ----------------
        ip_label = QLabel("IP Address:")
        ip_display = QTextEdit()
        ip_display.setText(ip)
        ip_display.setReadOnly(True)
        ip_display.setFixedHeight(30)

        layout.addWidget(ip_label)
        layout.addWidget(ip_display)

        # ---------------- Summary ----------------
        summary_label = QLabel("VirusTotal Summary:")
        summary_box = QTextEdit()
        summary_box.setReadOnly(True)

        if "error" in vt_data:
            summary_text = vt_data["error"]
        else:
            attributes = vt_data.get("data", {}).get("attributes", {})
            last_stats = attributes.get("last_analysis_stats", {})
            total_engines = sum(last_stats.values())

            summary_text = (
                f"Country: {attributes.get('country', 'N/A')}\n"
                f"ASN: {attributes.get('asn', 'N/A')} ({attributes.get('as_owner', 'N/A')})\n"
                f"Network: {attributes.get('network', 'N/A')}\n"
                f"Reputation Score: {attributes.get('reputation', 'N/A')}\n"
                f"Total Engines Analyzed: {total_engines}\n"
                f"Analysis Stats: {last_stats}"
            )

        summary_box.setText(summary_text)
        summary_box.setFixedHeight(110)
        layout.addWidget(summary_label)
        layout.addWidget(summary_box)

        # ---------------- Engine Details ----------------
        engines_label = QLabel("Engine Results:")
        self.engines_box = QTextEdit()
        self.engines_box.setReadOnly(True)

        if "error" in vt_data:
            engine_text = "No engine data available."
        else:
            engines = attributes.get("last_analysis_results", {})
            engine_lines = []
            for engine_name, info in engines.items():
                result = info.get("result") or "clean"
                category = info.get("category") or "undetected"
                engine_lines.append(f"{engine_name}: {result} ({category})")

            engine_text = "\n".join(engine_lines)

        self.engines_box.setText(engine_text)
        layout.addWidget(engines_label)
        layout.addWidget(self.engines_box)

        self.setLayout(layout)
        self.resize(700, 600)

# ---------------- DETAILS ----------------
class EventDetailsDialog(QDialog):
    def __init__(self, row, columns):
        super().__init__()
        self.setWindowTitle("Event Details")

        layout = QVBoxLayout()
        text = QTextEdit()
        text.setReadOnly(True)

        payload = ''.join(random.choices(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            k=200
        ))

        full_text = "\n".join([f"{col}: {row.get(col, '')}" for col in columns])
        full_text += f"\n\nGenerated Payload:\n{payload}"

        text.setText(full_text)
        layout.addWidget(text)
        self.setLayout(layout)
        self.resize(800, 600)

# ---------------- DASHBOARD ----------------
class APTDashboard(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("APT Real-Time Detection Dashboard")
        self.resize(1100, 1050)

        self.columns = [
            "timestamp",
            "user_id",
            "endpoint",
            "ip",
            "event_label",
            "event_confidence",
            "sequence_label",
            "sequence_confidence",
            "risk_score",
            "model_version"
        ]

        self.data = pd.DataFrame()
        self.active_filters = set(ACTION_TYPES)
        self.last_len = 0

        # ---------------- MAIN UI ----------------
        central = QWidget()
        self.setCentralWidget(central)
        self.main_layout = QVBoxLayout()
        central.setLayout(self.main_layout)

        # ---------------- FILTER ----------------
        filter_layout = QHBoxLayout()
        self.filter_buttons = {}

        for action in ACTION_TYPES:
            cb = QCheckBox(action)
            cb.setChecked(True)
            cb.stateChanged.connect(self.on_filter_change)

            cb.setStyleSheet(f"""
                QCheckBox::indicator {{
                    width: 15px;
                    height: 15px;
                    border-radius: 7px;
                    border: 2px solid #999;
                    background-color: transparent;
                }}

                QCheckBox::indicator:checked {{
                    background-color: {ACTION_COLORS[action]};
                    border: 2px solid #999;
                }}
            """)

            self.filter_buttons[action] = cb
            filter_layout.addWidget(cb)

        self.main_layout.addLayout(filter_layout)

        # ---------------- CHART + RIGHT PANEL ----------------
        chart_layout = QHBoxLayout()

        # LEFT: BAR CHART
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground("w")
        self.plot_widget.showGrid(x=True, y=True)
        chart_layout.addWidget(self.plot_widget, stretch=3)

        # RIGHT PANEL
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)

        # Kill Chain Title
        title = QLabel("APT Kill Chain")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        right_layout.addWidget(title)
        right_layout.addSpacing(8) 

        # Kill Chain Bars
        self.kill_bars = {}
        for stage in ["Recon", "Movement", "Privilege", "Exfil"]:
            right_layout.addSpacing(8) 
            right_layout.addWidget(QLabel(stage))

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(False)
            bar.setFixedHeight(4)
            bar.setStyleSheet("""
                QProgressBar {
                    background-color: #2a2a2a;  /* background line */
                    border: none;
                    border-radius: 2px;
                }

                QProgressBar::chunk {
                    background-color: #00eaff;   /* progress line color */
                    border-radius: 2px;
                }
            """)
            right_layout.addWidget(bar)
            self.kill_bars[stage] = bar
            right_layout.addSpacing(7)

        # Risk Donut
        self.risk_plot = FigureCanvas(Figure(figsize=(3, 3)))
        right_layout.addWidget(self.risk_plot)

        right_layout.addStretch()
        chart_layout.addWidget(right_panel, stretch=1)

        self.main_layout.addLayout(chart_layout)

        # ---------------- TABLE ----------------
        self.table = QTableWidget()
        # inside your APTDashboard __init__ after creating self.table
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.setColumnCount(len(self.columns))
        self.table.setHorizontalHeaderLabels(self.columns)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.cellDoubleClicked.connect(self.show_row_details)

        self.main_layout.addWidget(self.table)

        # ---------------- TIMER ----------------
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_ui)
        self.timer.start(2000)

    # -------------Right Click Menu--------------
    def show_context_menu(self, pos: QPoint):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return

        menu = QMenu()
        menu.addAction("Allow", lambda: self.handle_action(row, "allow"))
        menu.addAction("Block", lambda: self.handle_action(row, "block"))
        menu.addAction("IP Reputation", lambda: self.handle_action(row, "ip_reputation"))

        menu.exec(self.table.viewport().mapToGlobal(pos))

    # -------------Handle Menu Action-------------
    def handle_action(self, row, action):
        ip = self.table.item(row, self.columns.index("ip")).text()

        if action == "allow":
            print(f"Allow action for row {row}, IP {ip}")
        elif action == "block":
            print(f"Block action for row {row}, IP {ip}")
        elif action == "ip_reputation":
            self.show_ip_reputation_dialog(ip, row)

    # -----------== Virus Total----------------------
    def show_ip_reputation_dialog(self, ip, row):
        # Query VirusTotal first (we will cover this next)
        vt_info = self.query_virustotal_ip(ip)
        dlg = IPReputationDialog(ip, vt_info)
        dlg.exec()

    def query_virustotal_ip(self, ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}

        try:
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()  # <-- return full JSON dict
            else:
                return {"error": f"Failed to query VirusTotal: {resp.status_code}"}
        except Exception as e:
            return {"error": f"Error querying VirusTotal: {e}"}

    # ---------------- LOAD CSV ----------------
    def load_csv(self):
        try:
            df = pd.read_csv(CSV_FILE)
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

            if len(df) > self.last_len:
                new_rows = df.iloc[self.last_len:]
                self.data = pd.concat([self.data, new_rows], ignore_index=True).iloc[-MAX_EVENTS:]
                self.last_len = len(df)

        except Exception as e:
            print("CSV error:", e)

    # ---------------- FILTER ----------------
    def on_filter_change(self):
        self.active_filters = {
            a for a, cb in self.filter_buttons.items() if cb.isChecked()
        }

    def get_filtered_data(self):
        df = self.data.copy()
        if "event_label" in df:
            return df[df["event_label"].isin(self.active_filters)]
        return df

    # ---------------- SUSPICIOUS ----------------
    def is_suspicious(self, row):
        return (
            row.get("event_label") == "data_exfiltration"
            or float(row.get("risk_score", 0)) > 70
        )

    # ---------------- UPDATE ----------------
    def update_ui(self):
        self.load_csv()
        self.refresh_chart()
        self.refresh_table()
        self.update_kill_chain()
        self.update_risk()

    # ---------------- CHART ----------------
    def refresh_chart(self):
        df = self.get_filtered_data()

        if df.empty:
            self.plot_widget.clear()
            return

        df["date"] = df["timestamp"].dt.date
        grouped = df.groupby(["date", "event_label"]).size().unstack(fill_value=0)

        x = list(range(len(grouped.index)))
        self.plot_widget.clear()

         # Set x-axis labels to date strings
        date_labels = [str(d) for d in grouped.index]
        ax = self.plot_widget.getAxis("bottom")
        ax.setTicks([list(zip(x, date_labels))])

        bottom = [0] * len(x)

        for action in ACTION_TYPES:
            values = grouped[action].values if action in grouped else [0]*len(x)

            bar = pg.BarGraphItem(
                x=x,
                height=values,
                width=0.6,
                y0=bottom,
                brush=ACTION_COLORS[action]
            )

            self.plot_widget.addItem(bar)
            bottom = [bottom[i] + values[i] for i in range(len(values))]

        # ADD HERE
        vb = self.plot_widget.getViewBox()
        vb.setDefaultPadding(0)
        vb.setLimits(yMin=0)

        max_y = max(bottom) if bottom else 10
        self.plot_widget.setYRange(0, max_y * 1.1)

    # ---------------- KILL CHAIN ----------------
    def update_kill_chain(self):
        df = self.get_filtered_data()

        values = {}
        for stage, actions in KILL_CHAIN_MAPPING.items():
            values[stage] = df["event_label"].isin(actions).sum()

        max_val = max(values.values()) if values else 1

        for stage, value in values.items():
            percent = int((value / max_val) * 100) if max_val > 0 else 0
            self.kill_bars[stage].setValue(percent)

    # ---------------- RISK ----------------
    def update_risk(self):
        df = self.get_filtered_data()
        self.risk_plot.figure.clear()

        # Set figure background black
        self.risk_plot.figure.set_facecolor("#1f1f1f")
        ax = self.risk_plot.figure.add_subplot(111, facecolor="#1f1f1f")

        if df.empty:
            safe, risk = 1, 0
        else:
            suspicious = df.apply(self.is_suspicious, axis=1).sum()
            risk = suspicious / len(df)
            safe = 1 - risk

        ax.pie([safe, risk], colors=["#8DFF91", "#FF4848"], startangle=90,
               wedgeprops={'width': 0.3})

        # Add text inside donut (explicit white color)
        ax.text(0, 0.15, "Risk Score", color="white",
                fontsize=12, fontweight='normal', ha='center', va='center')
        ax.text(0, -0.15, f"{int(risk*100)}%", color="white",
                fontsize=20, fontweight='bold', ha='center', va='center')
        ax.axis('equal')

        self.risk_plot.draw()

    # ---------------- TABLE ----------------
    def refresh_table(self):
        df = self.get_filtered_data().sort_values("timestamp", ascending=False).head(200)

        self.table.setRowCount(len(df))

        for i, (_, row) in enumerate(df.iterrows()):
            for j, col in enumerate(self.columns):
                value = str(row.get(col, ""))
                item = QTableWidgetItem(value)

                if self.is_suspicious(row):
                    item.setBackground(pg.mkColor("#ff6b6b"))

                self.table.setItem(i, j, item)

    # ---------------- DETAILS ----------------
    def show_row_details(self, row, col):
        row_data = {
            self.columns[j]: self.table.item(row, j).text()
            for j in range(len(self.columns))
        }

        dlg = EventDetailsDialog(row_data, self.columns)
        dlg.exec()

# ---------------- RUN ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = APTDashboard()
    window.show()
    sys.exit(app.exec())
