import sys
import asyncio
from PySide6.QtWidgets import (QApplication, QMainWindow, QStackedWidget, QWidget, 
                               QVBoxLayout, QSplitter, QLabel)
from PySide6.QtCore import Qt
from qasync import QEventLoop

from ui.widgets import Sidebar
from ui.recon_view import ReconView
from ui.attack_view import AttackView
from ui.discovery_view import DiscoveryView
from ui.report_view import ReportView
from ui.asset_view import AssetView
from ui.identity_view import IdentityView
from ui.settings_view import SettingsView
from scanner import SecurityScanner
from version import get_full_version_string
from styles import StyleManager

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(get_full_version_string())
        self.resize(1400, 900)
        
        self.scanner = SecurityScanner()
        
        self.main_split = QSplitter(Qt.Orientation.Horizontal)
        
        self.sidebar = Sidebar()
        self.sidebar.currentRowChanged.connect(self.change_page)
        self.main_split.addWidget(self.sidebar)
        
        self.stack = QStackedWidget()
        self.asset_view = AssetView()
        self.recon_view = ReconView(self.scanner, asset_view=self.asset_view)
        self.attack_view = AttackView(self.scanner)
        self.discovery_view = DiscoveryView(self.scanner, self.recon_view)
        self.report_view = ReportView(self.scanner)
        
        self.identity_view = IdentityView()
        self.settings_view = SettingsView(self)
        
        self.stack.addWidget(self.recon_view)      # 0
        self.stack.addWidget(self.attack_view)     # 1
        self.stack.addWidget(self.identity_view)   # 2
        self.stack.addWidget(self.report_view)     # 3
        self.stack.addWidget(self.discovery_view)  # 4
        self.stack.addWidget(self.asset_view)      # 5
        self.stack.addWidget(self.settings_view)   # 6
        
        self.main_split.addWidget(self.stack)
        self.setCentralWidget(self.main_split)
        
        # Navigation Connections
        self.asset_view.asset_double_clicked.connect(self.on_asset_jump)
        
        # Style
        from styles import StyleManager
        self.setStyleSheet(StyleManager.get_qss("dark"))

    def change_page(self, index):
        self.stack.setCurrentIndex(index)
        self.sidebar.setCurrentRow(index) # Ensure sidebar reflects jump
    
    def on_asset_jump(self, asset_data):
        """Switches to ReconView and selects the asset."""
        self.change_page(0) # Recon is index 0
        url = asset_data.get("url")
        if url:
            self.recon_view.select_url(url)
    
    def toggle_theme(self, theme_name="dark"):
        self.setStyleSheet(StyleManager.get_qss(theme_name))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    
    win = MainWindow()
    win.show()
    
    with loop:
        loop.run_forever()
