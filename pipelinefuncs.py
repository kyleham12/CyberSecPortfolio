import os, json, time, logging, datetime
from typing import List

import azure.functions as func
import requests
from azure.eventhub import EventHubProducerClient, EventData

# ---------- Azure Functions App ----------
app = func.FunctionApp()

# ---------- App Settings ----------
EVENTHUB_CONN = os.environ["EVENTHUB_CONN"]                # Send SAS for eh-splunk
EVENTHUB_NAME = os.environ["EVENTHUB_NAME"]                # "eh-splunk"
HEC_URL       = os.environ["SPLUNK_HEC_URL"]               # e.g., https://<host>:8088/services/collector
HEC_TOKEN     = os.environ["SPLUNK_HEC_TOKEN"]
HEC_INDEX     = os.environ.get("SPLUNK_HEC_INDEX", "")     # optional
HEC_VERIFY    = os.environ.get("SPLUNK_HEC_VERIFY", "true").lower() == "true"

# ---------- HTTP session (reuse) ----------
session = requests.Session()
session.headers.update({"Authorization": f"Splunk {HEC_TOKEN}"})
session.trust_env = True  # honor proxies if present

# ---------- Event Hubs producer (for ingest) ----------
producer = EventHubProducerClient.from_connection_string(
    conn_str=EVENTHUB_CONN, eventhub_name=EVENTHUB_NAME
)

# ---------- Helpers ----------
def _epoch(x):
    try:
        xf = float(x)
        return xf if xf > 1_000_000_000 else time.time()
    except Exception:
        return time.time()

def heuristic_score(doc: dict) -> float:
    """
    +60 if event_code == 4625
    +30 if powershell detected (flag==1 or process contains 'powershell')
    +10 if off-hours (UTC hour <6 or >20)
    """
    score = 0
    code = str(doc.get("event_code", doc.get("EventCode", "")))
    if code == "4625":
        score += 60
    has_ps_flag = str(doc.get("powershell_script_detected")) == "1"
    has_ps_name = "powershell" in str(doc.get("process", "")).lower()
    if has_ps_flag or has_ps_name:
        score += 30
    hour = time.gmtime(_epoch(doc.get("_time", time.time()))).tm_hour
    if hour < 6 or hour > 20:
        score += 10
    return float(min(100.0, score))

def _post_to_splunk(ev: dict):
    payload = {"event": ev, "sourcetype": "_json"}
    if "host" in ev:
        payload["host"] = str(ev["host"])
    if "_time" in ev:
        payload["time"] = _epoch(ev["_time"])
    if HEC_INDEX:
        payload["index"] = HEC_INDEX

    # small retry loop
    for attempt in range(3):
        try:
            r = session.post(HEC_URL, json=payload, timeout=5, verify=HEC_VERIFY)
            r.raise_for_status()
            return
        except Exception as ex:
            if attempt == 2:
                raise
            time.sleep(0.5 * (attempt + 1))

def _parse_event_body(e: func.EventHubEvent) -> dict:
    """Robust parser: handles UTF-8 BOM and double-encoded JSON strings."""
    try:
        b = e.get_body().decode("utf-8", errors="replace") if e else ""
        s = b.lstrip("\ufeff").strip()  # strip BOM + whitespace

        # Try direct JSON
        try:
            return json.loads(s)
        except Exception:
            pass

        # Try if JSON was encoded as a string: "\"{...}\""
        if s.startswith('"') and s.endswith('"'):
            try:
                return json.loads(json.loads(s))
            except Exception:
                pass

        # Give up -> raw carrier
        return {"raw": b}
    except Exception:
        return {"raw": ""}

# ---------- HTTP: /api/ingest ----------
@app.route(route="ingest", auth_level=func.AuthLevel.FUNCTION)
def ingest(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except Exception:
        return func.HttpResponse("Invalid or missing JSON body", status_code=400)

    events = body if isinstance(body, list) else [body]
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

    payloads: List[EventData] = []
    for e in events:
        if isinstance(e, dict):
            e.setdefault("ingest_ts", now)
            e.setdefault("source", "splunk-webhook")
            payloads.append(EventData(json.dumps(e, separators=(",", ":"))))
        else:
            payloads.append(EventData(json.dumps({"event": e, "ingest_ts": now, "source": "splunk-webhook"})))

    try:
        batch = producer.create_batch()
        for p in payloads:
            try:
                batch.add(p)
            except ValueError:
                producer.send_batch(batch)
                batch = producer.create_batch()
                batch.add(p)
        if len(batch) > 0:
            producer.send_batch(batch)
        return func.HttpResponse("OK", status_code=200)
    except Exception as ex:
        logging.exception("Failed to send to Event Hubs")
        return func.HttpResponse(f"EH error: {ex}", status_code=500)

# ---------- HTTP: /api/score (free-tier scorer) ----------
@app.function_name(name="score")
@app.route(route="score", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def score_http(req: func.HttpRequest) -> func.HttpResponse:
    """
    Request:  {"inputs":[{ ...event... }, ...]}
    Response: {"scores":[float,...], "labels":[low|medium|high,...]}
    """
    try:
        body = req.get_json()
        inputs = body.get("inputs", [])
        scores, labels = [], []
        for doc in inputs:
            s = heuristic_score(doc)
            scores.append(s)
            labels.append("high" if s >= 80 else ("medium" if s >= 50 else "low"))
        return func.HttpResponse(json.dumps({"scores": scores, "labels": labels}),
                                 status_code=200, mimetype="application/json")
    except Exception as ex:
        return func.HttpResponse(str(ex), status_code=400)

# ---------- Normalization helpers ----------

def _maybe_json(s):
    try:
        if isinstance(s, (bytes, bytearray)): s = s.decode("utf-8", "ignore")
        if isinstance(s, str) and s.strip().startswith(("{", "[")):
            return json.loads(s)
    except Exception:
        pass
    return s

def _flatten(doc: dict) -> dict:
    """
    Accepts many common shapes and returns a flat event dict we can score:
    - {"event": {...}}                -> {...}
    - {"event": "{...json...}"}       -> {...}
    - {"body": "{...json...}"}        -> {...}
    - {"records":[{"body":...}]}      -> first record body
    - {"properties": {...}}           -> merge properties into top-level
    """
    if not isinstance(doc, dict):
        return {"raw": str(doc)}

    # Azure/EventHub batch style: {"records":[{...}]}
    if "records" in doc and isinstance(doc["records"], list) and doc["records"]:
        inner = doc["records"][0]
        return _flatten(inner if isinstance(inner, dict) else {"body": inner})

    # Generic wrappers
    for key in ("event", "body", "message"):
        if key in doc:
            inner = _maybe_json(doc[key])
            if isinstance(inner, dict):
                doc = inner
            elif isinstance(inner, str):
                # keep as raw if it's just a string
                return {"raw": inner}
            break

    # Merge common nested containers
    for key in ("properties", "detail", "data"):
        if key in doc and isinstance(doc[key], dict):
            merged = dict(doc)
            merged.update(doc[key])
            doc = merged

    return doc

def _normalize_for_heuristic(doc: dict) -> dict:
    """
    Ensure the keys the heuristic expects are present, with reasonable aliases.
    """
    # Aliases / case fixes
    if "event_code" not in doc:
        for k in ("EventCode", "eventCode", "event_id", "id"):
            if k in doc:
                doc["event_code"] = doc[k]; break

    if "process" not in doc:
        for k in ("Process_Name", "process_name", "Image", "image", "command", "cmd"):
            if k in doc:
                doc["process"] = str(doc[k]); break

    if "username" not in doc:
        for k in ("User", "user", "AccountName", "account"):
            if k in doc:
                doc["username"] = str(doc[k]); break

    if "src_ip" not in doc:
        for k in ("src", "source_ip", "ip", "ip_src", "client_ip"):
            if k in doc:
                doc["src_ip"] = str(doc[k]); break

    # _time: accept ISO string or epoch-like; otherwise leave as-is and _epoch() will handle
    if "_time" in doc:
        doc["_time"] = doc["_time"]

    return doc

# ---------- Event Hub consumer (robust unwrap + score) ----------
@app.function_name(name="eh_consumer")
@app.event_hub_message_trigger(
    arg_name="events",
    event_hub_name="%EVENTHUB_NAME%",
    connection="EVENTHUB_CONN_LISTEN",
    cardinality="many"
)
def eh_consumer(events: List[func.EventHubEvent]):
    # Support both many/one cardinality behavior just in case
    iterable = events if isinstance(events, list) else [events]

    for e in iterable:
        try:
            body = e.get_body().decode("utf-8") if e else ""
            doc_in = _maybe_json(body) if body else {}
            if not doc_in:
                doc_in = {"raw": body}

            # Unwrap common envelopes and normalize fields
            doc = _flatten(doc_in)
            doc = _normalize_for_heuristic(doc)

            # Score + enrich
            s = heuristic_score(doc)
            doc["threat_score"] = s
            doc["threat_label"] = "high" if s >= 80 else ("medium" if s >= 50 else "low")
            doc.setdefault("enriched_by", "heuristic")

            # If the event provided a 'host', passthrough to Splunk HEC envelope
            # so Splunk 'host' shows the true origin (not hec.<domain>)
            _post_to_splunk(doc)

        except Exception as ex:
            logging.exception(f"EH consumer failed: {ex}")

