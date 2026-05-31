"""CSS and HTML string constants for IOC Router UI."""
from __future__ import annotations

# ── Global styles: header, split layout, drawer ──────────────────────────────
GLOBAL_CSS_AND_HEADER = """
    <style>
    /* Scale entire UI to 80% on desktop; keep 100% on mobile for readability */
    @media (min-width: 768px) {
        html {
            zoom: 0.8;
        }
    }

    .fixed-app-header {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        text-align: center;
        padding: 2.55rem 1rem 1.45rem;
        background: linear-gradient(to bottom, #0e1117 0%, #0e1117 84%, rgba(14, 17, 23, 0) 100%);
        z-index: 9999;
    }

    .fixed-app-header__title {
        margin: 0;
        font-size: 2.25rem;
        font-weight: 700;
        line-height: 1.1;
        color: #f5f7fb;
        display: inline-block;
        letter-spacing: 0.01em;
        position: center;
    }

    .fixed-app-header__subtitle {
        margin: -0.08rem auto 0;
        font-size: 0.98rem;
        color: rgba(245, 247, 251, 0.72);
        line-height: 1.35;
        text-align: center;
        position: relative;
        left: -10px;
    }

    .fixed-app-header a {
        display: none !important;
    }

    .header-home-btn {
        background: none;
        border: none;
        cursor: pointer;
        padding: 0;
        margin: 0;
        color: inherit;
        font: inherit;
        text-decoration: none;
    }

    .header-home-btn:hover .fixed-app-header__title {
        opacity: 0.8;
        transition: opacity 0.15s ease;
    }

    .fixed-app-header:hover {
        opacity: 0.85;
        transition: opacity 0.15s ease;
    }

    .fixed-app-header-spacer {
        height: 128px;
    }

    @media (max-width: 768px) {
        .fixed-app-header {
            padding-top: 2.15rem;
            padding-bottom: 1.2rem;
        }

        .fixed-app-header__title {
            font-size: 1.55rem;
        }

        .fixed-app-header__subtitle {
            font-size: 0.82rem;
            left: 0;
        }

        .fixed-app-header-spacer {
            height: 100px;
        }

        /* Hide "Insert API Keys" text label — keep only the ☰ icon */
        .drawer-burger::after {
            display: none !important;
        }

        /* Mobile: show only emoji, hide text */
        .report-bug-btn {
            right: 0.75rem;
            padding: 6px 10px;
        }
        .report-bug-text {
            display: none;
        }
    }

    /* ── Split-screen layout ── */
    [data-testid="stHorizontalBlock"] {
        align-items: flex-start !important;
    }

    /* Main split: force true 50/50 and remove default column padding gap */
    div[data-testid="stHorizontalBlock"].ioc-main-split {
        gap: 1.5rem !important;
    }
    div[data-testid="stHorizontalBlock"].ioc-main-split
    > [data-testid="column"] {
        flex: 1 1 0 !important;
        min-width: 0 !important;
        width: 50% !important;
    }

    /* Divider between panels */
    div[data-testid="stHorizontalBlock"].ioc-main-split
    > [data-testid="column"]:first-child {
        border-right: 1px solid rgba(255, 255, 255, 0.08);
        padding-right: 1.25rem !important;
    }
    div[data-testid="stHorizontalBlock"].ioc-main-split
    > [data-testid="column"]:last-child {
        padding-left: 1.25rem !important;
    }

    /* Independent scroll panels on desktop */
    @media (min-width: 768px) {
        div[data-testid="stHorizontalBlock"].ioc-main-split
        > [data-testid="column"]:first-child > div:first-child {
            position: sticky;
            top: 130px;
            height: calc(100vh - 150px);
            overflow-y: auto;
            overflow-x: hidden;
        }

        div[data-testid="stHorizontalBlock"].ioc-main-split
        > [data-testid="column"]:last-child > div:first-child {
            position: sticky;
            top: 130px;
            height: calc(100vh - 150px);
            overflow-y: auto;
            overflow-x: hidden;
        }
    }

    /* Mobile: stack columns vertically */
    @media (max-width: 767px) {
        div[data-testid="stHorizontalBlock"].ioc-main-split {
            flex-direction: column !important;
        }
        div[data-testid="stHorizontalBlock"].ioc-main-split
        > [data-testid="column"] {
            width: 100% !important;
            border-right: none !important;
            padding-right: 0 !important;
            padding-left: 0 !important;
        }
    }

    /* ── API Key Drawer: transform Streamlit sidebar into overlay panel ── */
    section[data-testid="stSidebar"] {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        height: 100vh !important;
        width: 290px !important;
        min-width: 0 !important;
        max-width: 290px !important;
        z-index: 9990 !important;
        transform: translateX(-300px) !important;
        transition: transform 0.26s cubic-bezier(0.4,0,0.2,1) !important;
        background: #0d1117 !important;
        border-right: 1px solid #21262d !important;
        box-shadow: 4px 0 28px rgba(0,0,0,0.5) !important;
        overflow-y: auto !important;
    }
    /* Hide Streamlit's own sidebar toggle / resize handle */
    button[data-testid="collapsedControl"],
    section[data-testid="stSidebarResizeHandle"],
    .st-emotion-cache-1cypcdb {
        display: none !important;
    }
    /* Report Bug button in header */
    .report-bug-btn {
        position: absolute;
        right: 3rem;
        top: 50%;
        transform: translateY(-50%);
        font-size: 0.84rem;
        font-weight: 500;
        font-family: inherit;
        line-height: 1;
        cursor: pointer;
        color: rgba(245,247,251,0.82);
        user-select: none;
        z-index: 10001;
        padding: 8px 18px;
        border-radius: 6px;
        background: rgba(255,255,255,0.07);
        border: 1px solid rgba(255,255,255,0.18);
        transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
    }
    .report-bug-btn:hover {
        background: rgba(255,255,255,0.14);
        color: #fff;
        border-color: rgba(255,255,255,0.3);
    }

    /* Burger button in header */
    .drawer-burger {
        position: absolute;
        left: 1.1rem;
        top: 50%;
        transform: translateY(-50%);
        font-size: 1.45rem;
        line-height: 1;
        cursor: pointer;
        color: rgba(245,247,251,0.8);
        user-select: none;
        z-index: 10001;
        padding: 5px 7px;
        border-radius: 6px;
        transition: background 0.15s ease, color 0.15s ease;
    }
    .drawer-burger:hover {
        background: rgba(255,255,255,0.09);
        color: #fff;
    }
    /* Always-visible label next to burger button */
    .drawer-burger::after {
        content: 'Insert API Keys';
        position: absolute;
        left: calc(100% + 10px);
        top: 50%;
        transform: translateY(-50%);
        background: transparent;
        color: #c9d1d9;
        font-size: 0.78rem;
        font-weight: 600;
        white-space: nowrap;
        opacity: 1;
        pointer-events: none;
        border: none;
        box-shadow: none;
        padding: 0;
        border-radius: 0;
    }
    /* Hide label when drawer is open */
    .drawer-burger.open::after {
        display: none !important;
    }
    /* Backdrop */
    #drawer-backdrop {
        display: none;
        position: fixed;
        inset: 0;
        z-index: 9989;
        background: rgba(0,0,0,0.48);
    }
    /* Sidebar inner layout */
    section[data-testid="stSidebar"] > div:first-child {
        padding: 5.5rem 0.9rem 1.5rem !important;
    }
    section[data-testid="stSidebar"] [data-testid="stSidebarContent"] {
        background: #0d1117 !important;
    }
    section[data-testid="stSidebar"] label {
        font-size: 0.8rem !important;
        color: #8b95a8 !important;
        margin-bottom: 2px !important;
    }
    /* ── Sidebar text_input: single clean border, no Streamlit focus ring ── */
    /* Target the stTextInput wrapper to kill outer focus glow */
    section[data-testid="stSidebar"] .stTextInput > div {
        border: none !important;
        box-shadow: none !important;
        outline: none !important;
    }
    /* The actual BaseUI input container — this is the visible box */
    section[data-testid="stSidebar"] div[data-baseweb="input"] {
        background: #161b22 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px !important;
        box-shadow: none !important;
        outline: none !important;
        transition: border-color 0.15s ease !important;
    }
    section[data-testid="stSidebar"] div[data-baseweb="input"]:focus-within {
        border-color: #388bfd !important;
        box-shadow: none !important;
        outline: none !important;
    }
    /* Inner input element — transparent, no border, no outline */
    section[data-testid="stSidebar"] div[data-baseweb="input"] input {
        background: transparent !important;
        border: none !important;
        color: #c9d1d9 !important;
        font-size: 0.82rem !important;
        outline: none !important;
        box-shadow: none !important;
    }
    /* Hide "Press Enter to apply" helper text */
    section[data-testid="stSidebar"] [data-testid="InputInstructions"],
    section[data-testid="stSidebar"] small.instructions {
        display: none !important;
    }
    section[data-testid="stSidebar"] hr {
        border-color: #21262d !important;
        margin: 0.5rem 0 !important;
    }

    /* Ensure textarea text is always readable regardless of background override */
    [data-testid="stTextArea"] textarea {
        color: #e6edf3 !important;
    }

    /* Triage speed segmented control — render options vertically */
    .st-key-triage_speed_wrap_chat [data-testid="stSegmentedControl"] > div,
    .st-key-triage_speed_wrap_split [data-testid="stSegmentedControl"] > div {
        flex-direction: column !important;
        align-items: stretch !important;
        width: 100% !important;
        gap: 2px !important;
    }
    .st-key-triage_speed_wrap_chat [data-testid="stSegmentedControl"] label,
    .st-key-triage_speed_wrap_split [data-testid="stSegmentedControl"] label {
        width: 100% !important;
        justify-content: center !important;
    }

    </style>
    <div class="fixed-app-header" style="cursor:default;">
        <span class="drawer-burger" id="drawer-burger-btn">☰</span>
        <h1 class="fixed-app-header__title" onclick="window.location.reload();" style="cursor:pointer;" title="Back to home">🛡️ IOC Router 🛡️</h1>
        <p class="fixed-app-header__subtitle">IOC enrichment by minzelo</p>
        <button class="report-bug-btn" id="report-bug-header-btn"><span class="report-bug-text">Report Bug </span>🐞</button>
    </div>
    <div id="drawer-backdrop"></div>
    <div class="fixed-app-header-spacer"></div>
    """

# ── Landing page styles ───────────────────────────────────────────────────────
LANDING_CSS = """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Syne:wght@400;600;700;800&display=swap');

        /* Card: override Streamlit bordered container */
        [data-testid="stVerticalBlockBorderWrapper"] > div {
            border: 1px solid #2e333d !important;
            background-color: #13151a !important;
            border-radius: 16px !important;
            box-shadow: 0 0 0 1px rgba(255,255,255,0.03), 0 8px 40px rgba(0,0,0,0.35) !important;
            padding: 6px 10px 10px !important;
        }

        /* IOC textarea monospace */
        [data-testid="stVerticalBlockBorderWrapper"] textarea {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.83rem !important;
            background: transparent !important;
        }

        /* Run button (primary inside card) */
        [data-testid="stVerticalBlockBorderWrapper"] [data-testid="stBaseButton-primary"] button {
            border-radius: 10px !important;
            background: #e03b3b !important;
            border: none !important;
            box-shadow: 0 0 16px rgba(224,59,59,0.3) !important;
            font-size: 1rem !important;
        }
        [data-testid="stVerticalBlockBorderWrapper"] [data-testid="stBaseButton-primary"] button:hover {
            background: #ff6060 !important;
            box-shadow: 0 0 24px rgba(224,59,59,0.5) !important;
        }

        /* Hint pills row: style secondary buttons as pills */
        div.ioc-hint-row [data-testid="stBaseButton-secondary"] button {
            background: #13151a !important;
            border: 1px solid #242830 !important;
            border-radius: 20px !important;
            color: #6b7280 !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.7rem !important;
            padding: 4px 10px !important;
        }
        div.ioc-hint-row [data-testid="stBaseButton-secondary"] button:hover {
            border-color: #e03b3b !important;
            color: #ff6060 !important;
        }

        /* Checkbox label text in toolbar */
        [data-testid="stVerticalBlockBorderWrapper"] [data-testid="stCheckbox"] label p {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.72rem !important;
            color: #6b7280 !important;
        }
        </style>
        """
