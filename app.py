from flask import Flask, render_template, request, jsonify
from detector import analyze_url

app = Flask(__name__)

# Route 1: Home Page

@app.route("/")
def home():
    return render_template("index.html")

# Route 2: Analyze a URL

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URl to scan"}),400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    result = analyze_url(url)

    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)

