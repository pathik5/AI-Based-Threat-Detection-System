from flask import Flask, render_template, request
import hashlib
import pefile
import requests
import os
import mimetypes
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
app = Flask(__name__)

VIRUSTOTAL_API_KEY = "e977dbb712fde0f5c1fc57390d881482c6fcceca4dbe52ccd2ee6b3b03962440"

data = pd.read_csv('MalwareDataSet.csv')
data.groupby(data['legitimate']).size()
features = data.iloc[:,[0,1,2,3,4,5,6]].values 
ifMalware = data.iloc[:,7].values 
features_train, features_test, ifMalware_train, ifMalware_test = train_test_split(features, 
                                                                                  ifMalware, test_size=0.2)
rfModel = RandomForestClassifier(n_estimators=100)
rfModel.fit(features_train, ifMalware_train)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")



@app.route("/malware_analysis", methods=["GET", "POST"])
def malware_analysis():
    summary = None
    detailed = None
    if request.method == "POST":
        # Ensure the file is uploaded via an input with the name "file"
        if "file" in request.files:
            file = request.files["file"]
            filename = file.filename

            # Proceed only if the file is an EXE
            if filename.lower().endswith(".exe"):
                try:
                    # Reset the file pointer and read content for PE parsing
                    file.seek(0)
                    pe = pefile.PE(data=file.read())

                    # Extract key header features (ensure no trailing commas to avoid tuples)
                    AddressOfEntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    MajorLinkerVersion = pe.OPTIONAL_HEADER.MajorLinkerVersion
                    MajorImageVersion = pe.OPTIONAL_HEADER.MajorImageVersion
                    MajorOperatingSystemVersion = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
                    DllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
                    SizeOfStackReserve = pe.OPTIONAL_HEADER.SizeOfStackReserve
                    NumberOfSections = len(pe.sections)
                    
                    
                    # Build a feature vector (a 2D list) for model input.
                    features = [[
                        AddressOfEntryPoint,
                        MajorLinkerVersion,
                        MajorImageVersion,
                        MajorOperatingSystemVersion,
                        DllCharacteristics,
                        SizeOfStackReserve,
                        NumberOfSections
                       
                    ]]
                    
                    # Use the pre-trained model to predict.
                    prediction = rfModel.predict(features)
                    # Convert prediction to a plain list if needed.
                    prediction_list = prediction.tolist() if hasattr(prediction, "tolist") else list(prediction)

                    # Build the detailed report
                    detailed = {
                        "file_type": "exe",
                        "file" : filename,
                        "features": {
                            "AddressOfEntryPoint": AddressOfEntryPoint,
                            "MajorLinkerVersion": MajorLinkerVersion,
                            "MajorImageVersion": MajorImageVersion,
                            "MajorOperatingSystemVersion": MajorOperatingSystemVersion,
                            "DllCharacteristics": DllCharacteristics,
                            "SizeOfStackReserve": SizeOfStackReserve,
                            "NumberOfSections": NumberOfSections
                        },
                        "prediction": prediction_list
                    }

                    # If any element in the prediction array is 1, the file is malicious.
                    summary = "File is malicious" if any(val == 0 for val in prediction_list) else "File is safe"
                
                except Exception as e:
                    detailed = {"error": str(e)}
                    summary = "Error during PE analysis"
            else:
                summary = "The uploaded file is not an EXE."
    
    return render_template("malware_analysis.html", summary=summary, detailed=detailed)

@app.route("/url_detection", methods=["GET", "POST"])
def url_detection():
    summary = None
    detailed = None
    if request.method == "POST":
        if "url" in request.form:
            url = request.form["url"]
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            try:
                # Submit the URL for scanning
                url_scan = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
                vt_response = url_scan.json() if url_scan.status_code == 200 else None
                if vt_response and vt_response.get('data', {}).get('id'):
                    analysis_id = vt_response['data']['id']
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    analysis_response = requests.get(analysis_url, headers=headers)
                    analysis_data = analysis_response.json() if analysis_response.status_code == 200 else None
                    is_safe = (
                        analysis_data is None or 
                        (analysis_data.get('data', {})
                         .get('attributes', {})
                         .get('stats', {})
                         .get('malicious', 0) == 0)
                    )
                    detailed = {"safe": is_safe, "virustotal_report": analysis_data}
                else:
                    detailed = {"safe": None, "virustotal_report": vt_response}
            except requests.exceptions.RequestException as e:
                detailed = {"safe": False, "error": str(e)}
            
            if detailed.get("safe") is True:
                summary = "URL is safe"
            elif detailed.get("safe") is False:
                summary = "URL is not safe"
            else:
                summary = "URL scan result unavailable"
    return render_template("url_detection.html", summary=summary, detailed=detailed)

@app.route("/hash_file", methods=["GET", "POST"])
def hash_file():
    summary = None
    detailed = None
    if request.method == "POST":
        if "file" in request.files:
            file = request.files["file"]
            file_hash = calculate_hash(file)
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            try:
                response = requests.get(vt_url, headers=headers)
                vt_report = response.json() if response.status_code == 200 else None
                detailed = {"hash": file_hash, "virustotal_report": vt_report}
            except requests.exceptions.RequestException as e:
                detailed = {"hash": file_hash, "error": str(e)}
            summary = f"File hash is: {file_hash}"
    return render_template("hash_file.html", summary=summary, detailed=detailed)

@app.route("/extension_validation", methods=["GET", "POST"])
def extension_validation():
    summary = None
    detailed = None
    if request.method == "POST":
        if "file_ext" in request.files:
            file = request.files["file_ext"]
            original_filename = file.filename
            file_extension = os.path.splitext(original_filename)[1]  # includes the dot
            mime_type, encoding = mimetypes.guess_type(original_filename)
            if mime_type:
                ext_from_mime = mime_type.split("/")[-1].lower()
                is_valid = (ext_from_mime == file_extension.lower().lstrip('.'))
            else:
                is_valid = False
            detailed = {"is_valid": is_valid, "mime_type": mime_type, "extension": file_extension}
            summary = "Extension is valid" if is_valid else "Extension is not valid"
    return render_template("extension_validation.html", summary=summary, detailed=detailed)

def calculate_hash(file):
    hasher = hashlib.sha256()
    file.seek(0)
    while True:
        chunk = file.read(4096)
        if not chunk:
            break
        hasher.update(chunk)
    file.seek(0)
    return hasher.hexdigest()

if __name__ == "__main__":
    app.run(debug=True)
