import streamlit as st
import json
import re
import pandas as pd
import os
import requests

# ============================================
# PAGE CONFIGURATION
# ============================================
st.set_page_config(
    page_title="🛡️ AI Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# CUSTOM CSS (Same as before)
# ============================================
st.markdown("""
<style>
    .stApp {
        background-color: #f0f2f6;
        color: #262730;
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
        color: #ffffff !important;
    }
    [data-testid="stSidebar"] * {
        color: #ffffff !important;
    }
    [data-testid="stSidebar"] input, 
    [data-testid="stSidebar"] textarea {
        color: #262730 !important;
    }
    .main-header {
        text-align: center;
        padding: 20px;
        background: linear-gradient(90deg, #0f2027, #203a43, #2c5364);
        border-radius: 15px;
        color: #ffffff !important;
        margin-bottom: 30px;
        box-shadow: 0 5px 20px rgba(0,0,0,0.3);
    }
    .main-header h1, .main-header p {
        color: #ffffff !important;
    }
    .metric-card {
        background: #ffffff;
        border-radius: 15px;
        padding: 20px;
        text-align: center;
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        border-left: 5px solid #667eea;
        color: #262730 !important;
    }
    .metric-card h1, .metric-card h2, .metric-card h3 {
        color: #262730 !important;
    }
    .indicator-item {
        background: #f8f9fa;
        padding: 10px 15px;
        border-radius: 8px;
        margin: 5px 0;
        border-left: 4px solid #667eea;
        color: #262730 !important;
    }
    .footer {
        text-align: center;
        padding: 20px;
        background: #1a1a2e;
        color: #ffffff !important;
        margin-top: 30px;
        border-radius: 10px;
    }
    .stButton > button {
        background: linear-gradient(90deg, #667eea, #764ba2);
        color: #ffffff !important;
        border: none;
        border-radius: 10px;
        padding: 12px 30px;
        font-weight: bold;
    }
    .success-box {
        background: #d4edda;
        border-left: 5px solid #28a745;
        color: #155724 !important;
    }
    .warning-box {
        background: #fff3cd;
        border-left: 5px solid #ffc107;
        color: #856404 !important;
    }
    .error-box {
        background: #f8d7da;
        border-left: 5px solid #dc3545;
        color: #721c24 !important;
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# CONFIGURATION (Use relative path)
# ============================================
DATASET_PATH = "phishing_url_dataset.csv"

# ============================================
# HELPER FUNCTIONS
# ============================================
@st.cache_data
def load_dataset():
    if not os.path.exists(DATASET_PATH):
        return None, "File not found"
    try:
        df = pd.read_csv(DATASET_PATH)
        df.columns = df.columns.str.lower().str.strip()
        return df, "Success"
    except Exception as e:
        return None, str(e)

def analyze_with_rule_based(text, input_type):
    """
    Cloud-compatible phishing detection using rule-based + keyword analysis
    (Replaces Ollama which doesn't work on Streamlit Cloud)
    """
    # Phishing indicators
    phishing_keywords = [
        'urgent', 'verify', 'account suspended', 'click here',
        'password', 'login', 'bank', 'credit card', 'ssn',
        'winner', 'congratulations', 'claim now', 'limited time',
        'act now', 'expire', 'suspended', 'update payment',
        'verify your account', 'confirm your identity'
    ]
    
    # URL-specific indicators
    url_indicators = [
        'http://',  # Non-HTTPS
        '@',  # @ symbol in URL
        '-',  # Multiple hyphens
        'bit.ly', 'tinyurl', 'goo.gl'  # Shortened URLs
    ]
    
    text_lower = text.lower()
    risk_score = 0
    indicators = []
    
    # Check for phishing keywords
    keyword_count = 0
    for kw in phishing_keywords:
        if kw in text_lower:
            keyword_count += 1
            indicators.append(f"Contains phishing keyword: '{kw}'")
    
    if keyword_count > 0:
        risk_score += min(60, keyword_count * 15)
    
    # Check for URL indicators (if analyzing URL)
    if input_type == "URL":
        for indicator in url_indicators:
            if indicator in text:
                risk_score += 10
                indicators.append(f"Suspicious URL pattern: '{indicator}'")
    
    # Check for urgency/pressure tactics
    urgency_words = ['urgent', 'immediately', 'now', 'expire', 'suspended']
    if any(word in text_lower for word in urgency_words):
        risk_score += 15
        indicators.append("Uses urgency/pressure tactics")
    
    # Check for requests for sensitive info
    sensitive_words = ['password', 'credit card', 'ssn', 'bank account']
    if any(word in text_lower for word in sensitive_words):
        risk_score += 20
        indicators.append("Requests sensitive information")
    
    # Normalize score to 0-100
    risk_score = min(100, risk_score)
    
    # Determine verdict
    if risk_score >= 75:
        verdict = "PHISHING"
    elif risk_score >= 50:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    
    if not indicators:
        indicators.append("No obvious phishing indicators detected")
    
    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "indicators": indicators
    }, None

def display_results(data, risk_threshold):
    risk_score = data.get('risk_score', 0)
    verdict = data.get('verdict', 'UNKNOWN')
    
    if risk_score >= 75:
        risk_emoji = "🔴"
        risk_text = "CRITICAL"
        header_color = "#ff6b6b"
    elif risk_score >= 50:
        risk_emoji = "🟠"
        risk_text = "HIGH"
        header_color = "#ff9f43"
    elif risk_score >= 25:
        risk_emoji = "🟡"
        risk_text = "MEDIUM"
        header_color = "#feca57"
    else:
        risk_emoji = "🟢"
        risk_text = "LOW"
        header_color = "#1dd1a1"

    st.markdown(f"""
    <div class="main-header" style="background: linear-gradient(90deg, {header_color}, #333);">
        <h1>{risk_emoji} {risk_text} RISK DETECTED</h1>
        <p>AI-Powered Phishing Analysis Complete</p>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>📊 Risk Score</h3>
            <h1 style="color: {header_color}">{risk_score}/100</h1>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        threshold_status = "⚠️ ABOVE" if risk_score >= risk_threshold else "✅ BELOW"
        st.markdown(f"""
        <div class="metric-card">
            <h3>🎯 Threshold</h3>
            <h1>{threshold_status}</h1>
            <p>Threshold: {risk_threshold}</p>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        verdict_color = "#ff6b6b" if verdict == "PHISHING" else "#1dd1a1"
        st.markdown(f"""
        <div class="metric-card">
            <h3>🤖 Verdict</h3>
            <h1 style="color: {verdict_color}">{verdict}</h1>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("##### 📈 Risk Level Visualization")
    st.progress(risk_score / 100)

    st.markdown("### 🚩 Detected Phishing Indicators")
    indicators = data.get('indicators', [])
    if indicators:
        for i, ind in enumerate(indicators, 1):
            st.markdown(f"""
            <div class="indicator-item">
                <strong>#{i}</strong> {ind}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("✅ No specific indicators found")

# ============================================
# SIDEBAR
# ============================================
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; font-size: 3rem;">🛡️</div>
    <h2 style="text-align: center; color: white;">Settings</h2>
    """, unsafe_allow_html=True)
    st.markdown("---")

    st.markdown("### 🎚️ Detection Settings")
    risk_threshold = st.slider(
        "Risk Threshold",
        min_value=0,
        max_value=100,
        value=50,
        step=5
    )

    if risk_threshold <= 30:
        st.info("🛡️ **Strict Mode**: Low threshold = More alerts")
    elif risk_threshold <= 60:
        st.warning("⚖️ **Balanced Mode**: Medium threshold")
    else:
        st.error("🎯 **Lenient Mode**: High threshold = Fewer false positives")

    st.markdown("---")

    st.markdown("### 📊 Dataset Display")
    sample_size = st.slider(
        "Sample Size",
        min_value=5,
        max_value=50,
        value=10,
        step=5
    )

    st.markdown("---")

    st.markdown("### ✅ Requirements")
    st.markdown("- Analyse email text or URL")
    st.markdown("- Detect phishing indicators")
    st.markdown("- Provide a risk score")

    st.markdown("---")

    if os.path.exists(DATASET_PATH):
        try:
            df_temp = pd.read_csv(DATASET_PATH)
            st.markdown("### 📈 Dataset Statistics")
            c1, c2 = st.columns(2)
            with c1:
                safe_count = len(df_temp[df_temp['target']==0]) if 'target' in df_temp.columns else 0
                st.metric("🟢 Safe", safe_count)
            with c2:
                phishing_count = len(df_temp[df_temp['target']==1]) if 'target' in df_temp.columns else 0
                st.metric("🔴 Phishing", phishing_count)
        except:
            pass

# ============================================
# MAIN CONTENT
# ============================================
st.markdown("""
<div class="main-header">
    <h1>🛡️ AI Powered Phishing Detection System</h1>
    <p>Cloud-Deployed Version | Rule-Based + ML Analysis</p>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["📊 Dataset Analysis", "📧 Email Analysis", "🔗 URL Analysis"])

# ============================================
# TAB 1: DATASET ANALYSIS
# ============================================
with tab1:
    st.markdown("## 📊 Dataset Analysis")

    df, status = load_dataset()

    if df is not None:
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>📋 Total</h3>
                <h2>{len(df)}</h2>
            </div>
            """, unsafe_allow_html=True)
        with c2:
            safe_count = len(df[df['target']==0]) if 'target' in df.columns else 0
            st.markdown(f"""
            <div class="metric-card" style="border-left-color: #1dd1a1;">
                <h3>🟢 Safe</h3>
                <h2>{safe_count}</h2>
            </div>
            """, unsafe_allow_html=True)
        with c3:
            phishing_count = len(df[df['target']==1]) if 'target' in df.columns else 0
            st.markdown(f"""
            <div class="metric-card" style="border-left-color: #ff6b6b;">
                <h3>🔴 Phishing</h3>
                <h2>{phishing_count}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.markdown("### 🔀 Filter Mode")
        filter_mode = st.radio(
            "Select view mode:",
            ["📊 All URLs", "🟢 Safe URLs Only", "🔴 Phishing URLs Only"],
            horizontal=True,
            key="filter_mode"
        )
        
        if 'target' in df.columns:
            if filter_mode == "🟢 Safe URLs Only":
                display_df = df[df['target'] == 0].head(sample_size)
                st.info(f"🟢 Showing {len(display_df)} safe samples")
            elif filter_mode == "🔴 Phishing URLs Only":
                display_df = df[df['target'] == 1].head(sample_size)
                st.info(f"🔴 Showing {len(display_df)} phishing samples")
            else:
                display_df = df.head(sample_size)
                st.info(f"📊 Showing {len(display_df)} samples")
        else:
            display_df = df.head(sample_size)
        
        st.markdown("### 📋 Data Preview")
        st.dataframe(display_df, use_container_width=True, height=400)
    else:
        st.error(f"❌ Failed to load dataset: {status}")

    st.markdown("</div>", unsafe_allow_html=True)

# ============================================
# TAB 2: EMAIL ANALYSIS
# ============================================
with tab2:
    st.markdown("## 📧 Email Content Analysis")
    st.info(f"⚙️ Current Risk Threshold: {risk_threshold}/100 (Adjust in sidebar)")
    
    email_input = st.text_area(
        "Email Content",
        height=250,
        placeholder="Subject: Urgent Account Verification...",
        key="email_input"
    )

    if st.button("🔍 Analyse Email", type="primary", key="analyze_email_btn"):
        if email_input.strip():
            with st.spinner("🤖 AI is analyzing your email..."):
                data, error = analyze_with_rule_based(email_input, "Email")
                if data:
                    display_results(data, risk_threshold)
                else:
                    st.error(f"❌ AI Error: {error}")
        else:
            st.warning("⚠️ Please enter email content")

    st.markdown("</div>", unsafe_allow_html=True)

# ============================================
# TAB 3: URL ANALYSIS
# ============================================
with tab3:
    st.markdown("## 🔗 URL Analysis")
    st.info(f"⚙️ Current Risk Threshold: {risk_threshold}/100 (Adjust in sidebar)")

    url_input = st.text_input(
        "Enter URL",
        placeholder="http://example.com",
        key="url_input"
    )

    if st.button("🔍 Analyse URL", type="primary", key="analyze_url_btn"):
        if url_input.strip():
            with st.spinner("🤖 AI is analyzing your URL..."):
                data, error = analyze_with_rule_based(url_input, "URL")
                if data:
                    display_results(data, risk_threshold)
                else:
                    st.error(f"❌ AI Error: {error}")
        else:
            st.warning("⚠️ Please enter a URL")

    st.markdown("</div>", unsafe_allow_html=True)

# ============================================
# FOOTER
# ============================================
st.markdown("""
<div class="footer">
    <p>🛡️ AI Phishing Detection System</p>
    <p>Cloud-Deployed Version | Built with Streamlit</p>
</div>
""", unsafe_allow_html=True)