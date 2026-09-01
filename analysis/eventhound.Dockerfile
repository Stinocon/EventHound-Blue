# EventHound — immagine di ANALISI (motore analysis/ + GUI FastAPI :8700 + TUTTI i tool baked-in).
#
# Un'unica immagine self-contained: i runner scoprono i tool via PATH (tshark/zeek/dotnet) o
# sotto .tools/ (Hayabusa, EZ tools) — nessuna modifica al codice Python serve, basta che i
# binari esistano. Orchestrazione: docker-compose.yml di root (qdrant + rag-api + eventhound).
# La GUI raggiunge il RAG via RAG_API_URL=http://rag-api:8600 (percorso HTTP in app.py).
#
# Versioni dei binari come ARG (facili da bumpare). Il BUILD è la verifica: se un URL/versione
# non regge, il build fallisce qui — non a runtime.
#
# Base: Debian 13 Trixie (GLIBC 2.41+). Bookworm (12) ha GLIBC 2.36 — insufficiente per il
# binario GNU di Hayabusa (richiede 2.38+). Il repo OBS di Zeek qui sotto è allineato a Trixie.
FROM python:3.12-slim-trixie

# Versioni pinnate (verificate 2026-07-20). Bumpare qui.
ARG HAYABUSA_VERSION=3.10.0
ARG DOTNET_CHANNEL=9.0

ENV DEBIAN_FRONTEND=noninteractive

# ── 1. Dipendenze di sistema + tshark ────────────────────────────────────────────────
# tshark arriva da wireshark-common/tshark. curl/unzip/gnupg servono per i repo e i download.
RUN apt-get update && apt-get install -y --no-install-recommends \
        tshark \
        curl \
        unzip \
        ca-certificates \
        gnupg \
        libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Zeek (repo OBS: non è nei repo Debian di default) ──────────────────────────────
# Il binario finisce in /opt/zeek/bin/zeek → aggiunto al PATH più sotto.
RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_13/ /' \
        > /etc/apt/sources.list.d/security-zeek.list \
    && apt-get update && apt-get install -y --no-install-recommends zeek \
    && rm -rf /var/lib/apt/lists/*

# ── 3. Runtime .NET (per EvtxECmd/RECmd/MFTECmd, build net9) ───────────────────────────
# Script ufficiale dotnet-install: runtime-only, install in /usr/share/dotnet, symlink sul PATH.
# I runner settano già DOTNET_ROLL_FORWARD=Major.
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel ${DOTNET_CHANNEL} --runtime dotnet \
        --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && rm -f /tmp/dotnet-install.sh

# PATH: zeek (/opt/zeek/bin) + dotnet (/usr/local/bin già presente).
ENV PATH="/opt/zeek/bin:${PATH}"

# ── 4. Binari in .tools/ (gitignored nel repo; qui popolati a build-time con release LINUX) ──
# Hayabusa: binario + rules/ + config/ estratti in /app/.tools/hayabusa/ (find_binary li scopre).
ARG TARGETARCH
RUN mkdir -p /app/.tools/hayabusa \
    && if [ "$TARGETARCH" = "arm64" ]; then HAYSUFFIX="aarch64-gnu"; else HAYSUFFIX="x64-musl"; fi \
    && curl -fsSL -o /tmp/hayabusa.zip \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-${HAYSUFFIX}.zip" \
    && unzip -q /tmp/hayabusa.zip -d /app/.tools/hayabusa \
    && chmod +x /app/.tools/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-${HAYSUFFIX} \
    && rm -f /tmp/hayabusa.zip

# EZ tools net9: EvtxECmd/RECmd/MFTECmd → .dll sotto /app/.tools/{evtxecmd,recmd,mftcmd}/.
# I runner globbano **/<Tool>.dll sotto la rispettiva dir.
RUN for pair in evtxecmd:EvtxECmd recmd:RECmd mftcmd:MFTECmd; do \
        dir="${pair%%:*}"; tool="${pair##*:}"; \
        mkdir -p /app/.tools/${dir}; \
        curl -fsSL -o /tmp/${tool}.zip "https://download.ericzimmermanstools.com/net9/${tool}.zip"; \
        unzip -q /tmp/${tool}.zip -d /app/.tools/${dir}; \
        rm -f /tmp/${tool}.zip; \
    done

# ── 5. Dipendenze Python ──────────────────────────────────────────────────────────────
# Versioni allineate a analysis/pyproject.toml + analysis/gui/pyproject.toml (SOT). Stesso pattern
# di rag-api.Dockerfile: pip diretto nel python di sistema, niente venv nell'immagine.
RUN pip install --no-cache-dir \
        "duckdb>=1.0.0" \
        "fastapi>=0.110" \
        "uvicorn>=0.29" \
        "python-multipart>=0.0.9" \
        "httpx>=0.27"

# ── 6. Codice del motore + GUI ────────────────────────────────────────────────────────
# BUILD CONTEXT IS THE REPOSITORY ROOT, not ./analysis. The engine reaches `tools/` through
# sys.path — `gui/app.py` for the settings store, `ai/tools.py` for the scoring oracle (§6) and the
# enrichment gate, `ai/ollama_client.py` for the memory guard — and none of it was in this image,
# so the Settings view returned a 500 in Docker and the assistant could not import its own tools.
# COPY merges into the existing /app without touching the .tools/ populated above.
#
# `tools/` goes to /tools and NOT to /app/tools, because that is where the code looks: ANALISI_DIR
# is /app here, and every lookup is `<repo root>/tools` with the repo root computed as its parent.
# Keeping the paths the code already computes is cheaper than teaching five modules a second layout.
#
# The exclusions that used to live in analysis/.dockerignore moved to the ROOT .dockerignore with
# this change — Docker reads one ignore file, at the context root — and getting `.tools/` wrong
# there would ship the host's macOS binaries into a Linux image.
COPY analysis/ /app
COPY tools/ /tools

# PYTHONPATH=/app: engine/analytics resolve (app.py already inserts parents[1]; this is the belt).
ENV PYTHONPATH=/app
# The rag-api service on the compose network (overridable). The subprocess fallback is not needed here.
ENV RAG_API_URL=http://rag-api:8600

WORKDIR /app/gui
EXPOSE 8700

# Docker health: the GUI exposes /api/health (7 tools + decode); all baked in → always Available.
HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:8700/api/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8700", "--workers", "2"]
