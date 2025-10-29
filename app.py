import streamlit as st
import requests

st.title("GuardianEye: Phishing Detector")

user_input = st.text_area("Paste URL or email content here")

if st.button("Analyze"):
    if not user_input.strip():
        st.warning("Please enter text to analyze.")
    else:
        response = requests.post("http://localhost:8000/analyze", json={"text": user_input})
        if response.status_code == 200:
            data = response.json()
            st.subheader(f"Result: {data['result']}")
            st.write("**Rule-based reasons:**")
            for reason in data['rule_reasons']:
                st.write(f"- {reason}")
            st.write(f"**AI reason:** {data['ai_reason']}")
            if data['result'] == "Risky":
                st.warning("Be careful! This looks risky.")
            else:
                st.success("This looks safe.")
        else:
            st.error("Error analyzing input.")
