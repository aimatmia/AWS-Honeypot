
import os
import threading
import time
from datetime import timedelta
from decimal import Decimal

import boto3
import pandas as pd
from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)

# CONFIGURATION
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
TABLE_NAME = "CowrieLogs"
KNOWLEDGE_BASE_ID = "8OEJS30MCD"
GENERATION_MODEL_ID = "amazon.nova-micro-v1:0"

MAX_ITEMS = 50_000      # safety cap so a Scan can't run away on cost/time
CACHE_SECONDS = 60      # re-scan DynamoDB at most once a minute
COLUMNS = ["event_id", "timestamp", "command", "session_id", "src_ip", "input", "duration_ms",
           "username", "password"]
LOGIN_EVENTS = ["cowrie.login.failed", "cowrie.login.success"]

RANGES = {
    "24h": ("Last 24 hours", timedelta(hours=24)),
    "7d": ("Last 7 days", timedelta(days=7)),
    "30d": ("Last 30 days", timedelta(days=30)),
    "all": ("All time", None),
}

# AWS CLIENTS
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)
bedrock_agent_runtime = boto3.client("bedrock-agent-runtime", region_name=AWS_REGION)
bedrock_runtime = boto3.client("bedrock-runtime", region_name=AWS_REGION)


# DATA LOADING
def to_number(x):
    return float(x) if isinstance(x, Decimal) else x


def parse_ts(series: pd.Series) -> pd.Series:
    """Handles ISO strings (Cowrie default) or epoch seconds/milliseconds."""
    nums = pd.to_numeric(series.map(to_number), errors="coerce")
    if nums.notna().mean() > 0.5:
        unit = "ms" if nums.median() > 1e11 else "s"
        return pd.to_datetime(nums, unit=unit, utc=True, errors="coerce")
    return pd.to_datetime(series, utc=True, errors="coerce", format="ISO8601")


_cache = {"time": 0.0, "df": None}
_cache_lock = threading.Lock()


def _scan_table() -> pd.DataFrame:
    items, kwargs = [], {}
    while True:
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp or len(items) >= MAX_ITEMS:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    df = pd.DataFrame(items)
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = None
    df["timestamp"] = parse_ts(df["timestamp"])
    df["duration_ms"] = pd.to_numeric(df["duration_ms"].map(to_number), errors="coerce")
    df = _normalize(df)
    return df.dropna(subset=["timestamp"]).sort_values("timestamp")


def _blank(s: pd.Series) -> pd.Series:
    """True where a value is missing, empty, or the literal text 'none'."""
    return s.isna() | s.astype(str).str.strip().str.lower().isin(["", "none", "nan"])


def _normalize(df: pd.DataFrame) -> pd.DataFrame:
    """Merge  into command, and split old 'user:pass' login rows."""
    is_login = df["event_id"].astype(str).str.contains("login", case=False, na=False)
    inp = df["input"].fillna("").astype(str).str.strip()

    needs_split = (
        is_login
        & (_blank(df["username"]) | _blank(df["password"]))
        & inp.str.contains(":", regex=False)
    )
    if needs_split.any():
        parts = inp[needs_split].str.split(":", n=1, expand=True)
        df.loc[needs_split, "username"] = parts[0]
        df.loc[needs_split, "password"] = parts[1]

    df["command_raw"] = df["command"]

    use_input = _blank(df["command"]) & ~_blank(df["input"]) & ~is_login
    df["command"] = df["command"].where(~use_input, df["input"])

    return df


def load_data(force: bool = False) -> pd.DataFrame:
    """Cached scan of the table (replaces Streamlit's @st.cache_data)."""
    with _cache_lock:
        fresh = _cache["df"] is not None and time.time() - _cache["time"] < CACHE_SECONDS
        if force or not fresh:
            _cache["df"] = _scan_table()
            _cache["time"] = time.time()
        return _cache["df"]


def fmt_rows(df: pd.DataFrame, cols: list) -> list:
    """DataFrame -> list of plain dicts (timestamps as text, blanks for missing)."""
    out = df[cols].copy()
    if "timestamp" in out.columns:
        out["timestamp"] = out["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    if "first_seen" in out.columns:
        out["first_seen"] = out["first_seen"].dt.strftime("%Y-%m-%d %H:%M:%S")
    if "last_seen" in out.columns:
        out["last_seen"] = out["last_seen"].dt.strftime("%Y-%m-%d %H:%M:%S")
    out = out.astype(object).where(out.notna(), "")
    return out.to_dict("records")


# DASHBOARD
@app.route("/")
def dashboard():
    range_key = request.args.get("range", "7d")
    if range_key not in RANGES:
        range_key = "7d"

    common = {
        "ranges": {k: v[0] for k, v in RANGES.items()},
        "range_key": range_key,
        "table_name": TABLE_NAME,
        "region": AWS_REGION,
        "cache_seconds": CACHE_SECONDS,
    }

    try:
        data = load_data(force=request.args.get("refresh") == "1")
    except Exception as e:
        print("DASHBOARD ERROR:", str(e))
        return render_template(
            "dashboard.html",
            status="error",
            message=(
                f"Could not read table '{TABLE_NAME}' in {AWS_REGION}: {e}. "
                "Check AWS credentials, region, and that the IAM role allows dynamodb:Scan."
            ),
            **common,
        )

    if data.empty:
        return render_template(
            "dashboard.html", status="empty",
            message="No events found in the table yet.", **common,
        )

    # Time-range filter
    delta = RANGES[range_key][1]
    df = data
    if delta is not None:
        df = data[data["timestamp"] >= pd.Timestamp.now(tz="UTC") - delta]

    if df.empty:
        return render_template(
            "dashboard.html", status="empty",
            message="No events in this time range.", **common,
        )

    raw_text = df["command_raw"].fillna("").astype(str).str.strip()
    df = df.assign(cmd=raw_text.str.split().str[0].fillna(""))

    cmds = df[
        (df["event_id"] != "cowrie.command.failed")
        & (df["cmd"] != "")
        & (df["cmd"].str.lower() != "none")
    ]

    # Headline numbers
    valid_sessions = df[df["session_id"].notna() & (df["session_id"] != "none")]
    valid_ips = df[df["src_ip"].notna() & (df["src_ip"] != "none")]
    avg_duration = (
        f"{df['duration_ms'].mean():,.0f}" if df["duration_ms"].notna().any() else "n/a"
    )
    login_attempts = int(df["event_id"].isin(["cowrie.login.failed", "cowrie.login.success"]).sum())

    # Events over time
    freq = "h" if range_key in ("24h", "7d") else "D"
    over_time = df.set_index("timestamp").resample(freq).size()
    fmt = "%Y-%m-%d %H:00" if freq == "h" else "%Y-%m-%d"
    time_labels = [t.strftime(fmt) for t in over_time.index]
    time_values = [int(v) for v in over_time.values]

    # Top commands / IPs
    top_cmds = cmds["cmd"].value_counts().head(10)
    top_ips = valid_ips["src_ip"].value_counts().head(10)

    # Sessions (one row per attacker session)
    sessions = (
        valid_sessions.groupby("session_id")
        .agg(
            src_ip=("src_ip", "first"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            events=("event_id", "count"),
        )
        .sort_values("last_seen", ascending=False)
        .reset_index()
        .head(200)
    )

    # Most recent events
    recent = df.sort_values("timestamp", ascending=False).head(50)

    return render_template(
        "dashboard.html",
        status="ok",
        total_events=f"{len(df):,}",
        total_attackers=f"{valid_ips['src_ip'].nunique():,}",
        total_sessions=f"{valid_sessions['session_id'].nunique():,}",
        avg_duration=avg_duration,
        login_attempts=f"{login_attempts:,}",
        time_labels=time_labels,
        time_values=time_values,
        top_commands=[[str(k), int(v)] for k, v in top_cmds.items()],
        top_ips=[[str(k), int(v)] for k, v in top_ips.items()],
        sessions=fmt_rows(sessions, ["session_id", "src_ip", "first_seen", "last_seen", "events"]),
        recent=fmt_rows(recent, ["timestamp", "src_ip", "session_id", "username", "password", "command"]),
        **common,
    )


@app.route("/session/<session_id>")
def session_detail(session_id):
    """Events for one session (used by the 'Inspect a session' dropdown)."""
    try:
        data = load_data()
        rows = data[data["session_id"] == session_id].sort_values("timestamp")
        return jsonify(fmt_rows(rows, ["timestamp", "src_ip", "username", "password", "command", "duration_ms"]))
    except Exception as e:
        print("SESSION ERROR:", str(e))
        return jsonify([]), 500


# RAG CHATBOT 
@app.route("/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json()
        question = data.get("question", "").strip()

        if not question:
            return jsonify({"answer": "Please enter a question."})

        # Retrieve information from the managed knowledge base
        response = bedrock_agent_runtime.retrieve(
            knowledgeBaseId=KNOWLEDGE_BASE_ID,
            retrievalQuery={"text": question},
            retrievalConfiguration={
                "managedSearchConfiguration": {"numberOfResults": 5}
            },
        )

        retrieved_text = []
        for result in response.get("retrievalResults", []):
            text = result.get("content", {}).get("text", "")
            if text:
                retrieved_text.append(text)

        if not retrieved_text:
            return jsonify({"answer": "I could not find relevant Cowrie log information."})

        context = "\n\n".join(retrieved_text)

        prompt = f"""
You are a cybersecurity assistant analyzing Cowrie SSH honeypot logs.

Answer the user's question using ONLY the Cowrie log information
provided below.

Do not invent information.

If the answer cannot be determined from the provided information,
say that there is not enough information in the retrieved Cowrie logs.

Cowrie log information:

{context}

User question:

{question}

Give a short and clear answer.
"""

        response = bedrock_runtime.converse(
            modelId=GENERATION_MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 300, "temperature": 0},
        )

        answer = response["output"]["message"]["content"][0]["text"]
        return jsonify({"answer": answer})

    except Exception as e:
        print("CHAT ERROR:", str(e))
        return jsonify({"answer": "An error occurred while processing the question."}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=False)
