class StyleManager:
    @staticmethod
    def get_qss(theme="dark"):
        is_dark = theme == "dark"
        
        # Windows 11 Fluent Design - Professional Color Palette
        # Elite Sci-Fi / Cyber Obsidian Theme
        if is_dark:
            # Deep Space Obsidian
            bg_app = "#0b0b0d"
            bg_surface = "rgba(20, 20, 25, 0.7)"
            bg_card = "rgba(30, 30, 35, 0.5)"
            bg_elevated = "#1a1a1f"
            bg_sidebar = "#08080a"
            
            text_primary = "#ffffff"
            text_secondary = "#a0a4b8"
            text_tertiary = "#62657a"
            
            # Neon Accents (The "Bullshit" as the user says - High End Visuals)
            accent = "#60cdff"        # Electric Cyan
            accent_secondary = "#bd93f9" # Neon Purple
            accent_tertiary = "#ff79c6"  # Cyber Pink
            
            border_subtle = "rgba(255, 255, 255, 0.04)"
            border_default = "rgba(96, 205, 255, 0.15)"
            border_neon = "rgba(96, 205, 255, 0.4)"
            
            success = "#50fa7b"
            warning = "#f1fa8c"
            danger = "#ff5555"
            
            surface_hover = "rgba(96, 205, 255, 0.08)"
            surface_selected = "rgba(96, 205, 255, 0.15)"
        else:
            # Clean High-Contrast Light (Keep for functionality)
            bg_app = "#f8f9fa"
            bg_surface = "#ffffff"
            bg_card = "#f1f3f5"
            bg_sidebar = "#e9ecef"
            text_primary = "#212529"
            text_secondary = "#495057"
            accent = "#0078d4"
            border_default = "rgba(0, 0, 0, 0.1)"
            success = "#28a745"
            danger = "#dc3545"

        return f"""
        /* === ELITE SCI-FI OVERHAUL === */
        * {{
            font-family: 'Segoe UI Variable Display', 'Inter', 'Segoe UI', sans-serif;
            outline: none;
        }}
        
        QMainWindow {{
            background-color: {bg_app};
            background-image: qradialgradient(cx:0.5, cy:0.5, radius:1, fx:0.5, fy:0.5, stop:0 #1a1a2e, stop:1 {bg_app});
        }}
        
        QWidget {{
            background-color: transparent;
            color: {text_primary};
        }}

        /* === GLASS PANEL EFFECT === */
        QFrame[class~="card"], QTabWidget::pane {{
            background-color: {bg_card};
            border: 1px solid {border_default};
            border-radius: 12px;
        }}
        
        /* === SIDEBAR (NAV RAIL) === */
        QListWidget#sidebar {{
            background-color: {bg_sidebar};
            border-right: 1px solid {border_subtle};
            min-width: 75px;
            max-width: 75px;
        }}
        QListWidget#sidebar::item {{
            height: 70px;
            margin: 10px 8px;
            border-radius: 12px;
            color: {text_tertiary};
            font-size: 10px;
            font-weight: 800;
        }}
        QListWidget#sidebar::item:selected {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {accent}33, stop:1 {accent_secondary}33);
            color: {accent};
            border: 1px solid {border_neon};
        }}
        QListWidget#sidebar::item:hover:!selected {{
            background-color: {surface_hover};
            color: {text_secondary};
        }}
        
        /* === MODERN TABLES === */
        QTableWidget {{
            background-color: {bg_surface};
            border: 1px solid {border_subtle};
            border-radius: 12px;
            gridline-color: transparent;
            font-family: 'Cascadia Code', 'Consolas', monospace;
            font-size: 13px;
        }}
        QTableWidget::item {{
            padding: 10px;
            border-bottom: 1px solid {border_subtle};
        }}
        QTableWidget::item:selected {{
            background-color: {surface_selected};
            color: {accent};
            font-weight: bold;
        }}
        QHeaderView::section {{
            background-color: transparent;
            color: {accent};
            padding: 12px;
            border: none;
            border-bottom: 2px solid {border_default};
            font-weight: 900;
            font-size: 11px;
            text-transform: uppercase;
        }}
        
        /* === NEON INPUTS === */
        QLineEdit, QTextEdit, QPlainTextEdit {{
            background-color: rgba(0, 0, 0, 0.4);
            color: {accent};
            border: 1px solid {border_default};
            border-radius: 8px;
            padding: 12px;
            font-family: 'Cascadia Code', 'Consolas', monospace;
        }}
        QLineEdit:focus, QTextEdit:focus {{
            border: 1px solid {accent};
            background-color: rgba(0, 0, 0, 0.6);
        }}
        
        /* === SCI-FI BUTTONS === */
        QPushButton {{
            background-color: {bg_elevated};
            color: {text_primary};
            border: 1px solid {border_default};
            padding: 8px 20px;
            border-radius: 8px;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 12px;
        }}
        QPushButton:hover {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {accent}44, stop:1 {accent_secondary}44);
            border-color: {accent};
            color: #fff;
        }}
        
        /* Cyber Action Button */
        QPushButton#btn-vuln, QPushButton[class~="btn-vuln"] {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {danger}88, stop:1 {accent_tertiary}88);
            border: 1px solid {danger};
            color: #fff;
        }}
        
        /* === TABS === */
        QTabWidget::pane {{
            margin-top: -1px;
        }}
        QTabBar::tab {{
            background: transparent;
            color: {text_tertiary};
            padding: 10px 20px;
            font-weight: 800;
            text-transform: uppercase;
            font-size: 11px;
        }}
        QTabBar::tab:selected {{
            color: {accent};
            border-bottom: 3px solid {accent};
            background: rgba(96, 205, 255, 0.05);
        }}
        
        /* === SCROLLBARS (MINIMALIST) === */
        QScrollBar:vertical {{
            background: transparent;
            width: 6px;
        }}
        QScrollBar::handle:vertical {{
            background: {border_neon};
            border-radius: 3px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {accent};
        }}
        
        /* === HEADERS === */
        QLabel#h1 {{
            font-size: 32px;
            font-weight: 900;
            color: {accent};
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        QLabel#h2 {{
            font-size: 18px;
            font-weight: 800;
            color: {accent_secondary};
            text-transform: uppercase;
            padding-bottom: 5px;
        }}

        /* === SPLITTER === */
        QSplitter::handle {{
            background-color: {border_subtle};
        }}
        QSplitter::handle:hover {{
            background-color: {accent};
        }}
        """

