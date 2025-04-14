# Import Libraries
import streamlit as st
import requests
from PIL import Image
import pytesseract
import re
import io
import pandas as pd  # Add pandas to load dataset

# Load dataset (hidden initially)
try:
    dataset = pd.read_csv('dataset_phishing.csv')  # Make sure the dataset is in the same folder
    # st.write("Dataset loaded successfully!")  # 🔴 REMOVE THIS
except FileNotFoundError:
    st.error("Dataset not found. Please make sure 'dataset_phishing.csv' is in the same folder as this app.py.")
    st.stop()

# Streamlit App Title
st.title("🔍 Phishing URL & Image Detector")

# Configure Tesseract Path
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'  # Adjust path as needed

# VirusTotal API function
def check_site_categories(url):
    api_key = 'daf5975188a2ca61093f42b7e730d27f235941145c205cabf036209101628722'
    api_endpoint = f'https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={url}'

    try:
        response = requests.get(api_endpoint, timeout=10)
        response.raise_for_status()
        result = response.json()

        if result.get('response_code') == 1:
            categories_details = [
                (scan_engine, details['result'])
                for scan_engine, details in result.get('scans', {}).items()
                if details['result'] in ['malware site', 'phishing site', 'malicious site']
            ]
            return len(categories_details), categories_details
        else:
            return 0, []

    except requests.RequestException as e:
        st.error(f"Error while connecting to VirusTotal: {e}")
        return 0, []

# Extract URLs from text
def extract_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    return urls

# Sidebar Selection
option = st.sidebar.selectbox("Choose Detection Mode", ["Image Detection", "Manual URL Check"])

# If Image Detection
if option == "Image Detection":
    st.subheader("🖼 Upload an Image")
    uploaded_file = st.file_uploader("Upload an image (with potential URLs)", type=["jpg", "jpeg", "png"])

    if uploaded_file:
        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded Image", use_column_width=True)

        # OCR to extract text
        text = pytesseract.image_to_string(image)
        urls = extract_urls(text)

        if urls:
            st.write("🔗 URLs found in the image:")
            for url in urls:
                st.write(url)
                count, details = check_site_categories(url)

                if count > 0:
                    st.error(f"⚠ Warning: {url} is flagged!")
                    for engine, result in details:
                        st.write(f"Engine: {engine} | Result: {result}")
                else:
                    st.success(f"✅ {url} seems safe!")

            # ✅ Show dataset only after image is processed
            st.write("Here are some known phishing URLs from the dataset:")
            st.dataframe(dataset)

        else:
            st.info("No URLs found in the image.")

# If Manual URL Check
elif option == "Manual URL Check":
    st.subheader("🔗 Enter URL Manually")

    manual_url = st.text_input("Enter the URL to check:")

    if st.button("Check URL"):
        if manual_url:
            count, details = check_site_categories(manual_url)

            if count > 0:
                st.error(f"⚠ Warning: {manual_url} is flagged!")
                for engine, result in details:
                    st.write(f"Engine: {engine} | Result: {result}")
            else:
                st.success(f"✅ {manual_url} seems safe!")

            # ✅ Show dataset only after checking URL
            st.write("Here are some known phishing URLs from the dataset:")
            st.dataframe(dataset)

        else:
            st.warning("Please enter a URL to check.")
