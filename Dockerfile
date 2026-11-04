FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gatekeeper ./gatekeeper
COPY run_crew.py register_crew.py ./
# Agent ids and keys, room rules and the watchlist live here; mount it so they survive restarts.
VOLUME /app/state
CMD ["python", "-u", "run_crew.py"]
