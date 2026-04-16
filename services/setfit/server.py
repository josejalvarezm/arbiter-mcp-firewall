"""
Arbiter SetFit Shadow Classifier Service.

HTTP API for the shadow-tier classifier. Wraps a SetFit model
(sentence-transformers/all-MiniLM-L6-v2 fine-tuned on boundary
violation examples) and exposes a single /classify endpoint.

Usage:
    # With a trained model checkpoint:
    python server.py --model ./checkpoint --port 8099

    # Mock mode (for testing without a GPU/model):
    python server.py --mock --port 8099
"""

import argparse
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler


def create_handler(classifier):
    """Create a request handler with the given classifier function."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/classify":
                self.send_error(404, "Not found")
                return

            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 1_000_000:  # 1MB limit
                self.send_error(413, "Payload too large")
                return

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON")
                return

            text = data.get("text", "")
            if not isinstance(text, str):
                self.send_error(400, "'text' must be a string")
                return

            start = time.perf_counter()
            label, confidence = classifier(text)
            latency_ms = (time.perf_counter() - start) * 1000

            response = json.dumps(
                {"label": label, "confidence": round(confidence, 4)}
            ).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format, *args):
            # Suppress default logging; use structured output instead
            pass

    return Handler


def mock_classifier(text: str) -> tuple[str, float]:
    """Keyword-based mock classifier for testing without a real model."""
    danger_words = {
        "password", "credential", "secret", "token", "api_key",
        "ssh_key", "private_key", "access_key",
    }
    words = set(text.lower().split())
    hits = words & danger_words
    if hits:
        return "unsafe", min(0.5 + len(hits) * 0.15, 0.99)
    return "safe", 0.95


def load_setfit_classifier(model_path: str):
    """Load a trained SetFit model and return a classifier function."""
    from setfit import SetFitModel

    model = SetFitModel.from_pretrained(model_path)

    def classify(text: str) -> tuple[str, float]:
        prediction = model.predict([text])
        probabilities = model.predict_proba([text])

        label = str(prediction[0])
        confidence = float(probabilities[0].max())
        return label, confidence

    return classify


def main():
    parser = argparse.ArgumentParser(description="Arbiter SetFit Classifier Service")
    parser.add_argument("--model", type=str, help="Path to trained SetFit model checkpoint")
    parser.add_argument("--mock", action="store_true", help="Use mock classifier (no model needed)")
    parser.add_argument("--port", type=int, default=8099, help="Port to listen on")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind to")
    args = parser.parse_args()

    if args.mock:
        classifier = mock_classifier
        print(f"[arbiter-setfit] Mock classifier on {args.host}:{args.port}")
    elif args.model:
        classifier = load_setfit_classifier(args.model)
        print(f"[arbiter-setfit] Model loaded from {args.model}, serving on {args.host}:{args.port}")
    else:
        parser.error("Either --model or --mock is required")

    server = HTTPServer((args.host, args.port), create_handler(classifier))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[arbiter-setfit] Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
