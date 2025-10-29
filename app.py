import streamlit as st
import requests
import json

st.set_page_config(page_title="GuardianEye", page_icon="👁️", layout="wide")

st.title("👁️ GuardianEye - Phishing Detection System")
st.markdown("A comprehensive phishing detection system using AI and rule-based analysis")

# Backend URL - FIXED to use localhost
BACKEND_URL = "http://localhost:8000"

# Input section
col1, col2 = st.columns([2, 1])

with col1:
    url_input = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
    email_input = st.text_area("Or enter email text to analyze:", placeholder="Dear user, please verify your account...")
    
    analyze_btn = st.button("Analyze for Phishing", type="primary")

with col2:
    st.info("""
    **What we check:**
    - ✅ Google Safe Browsing API
    - ✅ Suspicious domain patterns  
    - ✅ Malicious keywords
    - ✅ AI-based content analysis
    - ✅ Structural anomalies
    """)

# Results section
if analyze_btn and (url_input or email_input):
    st.subheader("Analysis Results")
    
    with st.spinner("Analyzing content for phishing indicators..."):
        try:
            # Prepare request data
            data = {}
            if url_input:
                data["url"] = url_input
            if email_input:
                data["email_text"] = email_input
            
            # Call your backend with error handling
            response = requests.post(f"{BACKEND_URL}/analyze", json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                # Display results
                if result["is_phishing"]:
                    st.error(f"🚨 **PHISHING DETECTED!** (Confidence: {result['confidence']:.0%})")
                    st.write(f"**Detection Method:** {result['detection_method']}")
                    st.write(f"**Reasons:**")
                    for reason in result["reasons"]:
                        st.write(f"- {reason}")
                else:
                    st.success(f"✅ **SAFE** (Confidence: {result['confidence']:.0%})")
                    st.write(f"**Detection Method:** {result['detection_method']}")
                    if result["reasons"]:
                        st.write(f"**Notes:** {', '.join(result['reasons'])}")
                
                st.write(f"**Message:** {result['message']}")
                
            else:
                st.error(f"Backend error: {response.status_code} - {response.text}")
                
        except requests.exceptions.ConnectionError:
            st.error("❌ **Backend server is not running!**")
            st.info("Please make sure your backend is running on port 8000")
        except requests.exceptions.Timeout:
            st.error("⏰ **Backend timeout!** The analysis took too long.")
        except Exception as e:
            st.error(f"💥 **Unexpected error:** {str(e)}")

# Add a test section
st.divider()
st.subheader("Quick Test")
if st.button("Test with Example URLs"):
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Safe URL:**")
        st.code("https://github.com")
    
    with col2:
        st.write("**Suspicious URL:**")
        st.code("http://paypal-security-login.tk")