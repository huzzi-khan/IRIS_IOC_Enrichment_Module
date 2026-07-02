from flask import Flask, request, jsonify
from enricher import enrich_observable

app = Flask(__name__)

@app.route("/webhook", methods=["POST"])
def webhook():
    """
    IRIS calls this endpoint automatically
    when an IOC is created in a case.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "no data received"}), 400

    print(f"Webhook received: {data}")

    # Extract case ID and IOC from webhook payload
    case_id  = data.get("case_id")
    ioc      = data.get("ioc")

    if not case_id or not ioc:
        return jsonify({"error": "missing case_id or ioc"}), 400

    # Run enrichment
    enrich_observable(case_id, ioc)

    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)