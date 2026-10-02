# Noctis — The Agile Monkeys presentation script

Target length: **about 2:15 at a calm pace**.

The screens use deterministic synthetic data. The synthetic label stays visible during the whole recording so no card is presented as historical evidence.

## Script

### 00:00–00:25 — Curiosity

**Say:**

I have always been interested in cybersecurity, especially the underground side: ransomware groups, how they organize, where they communicate, and how investigators connect identities and infrastructure.

That curiosity made me want to build a small threat-intelligence platform for myself.

**Show:** `/presentation` — overview. Pause on the title and the signal field.

### 00:25–00:55 — What Noctis became

**Say:**

Noctis started mainly as Telegram collection and classification. It grew into a long-running Go daemon that also collects paste sites, forums and RSS or web feeds, archives the raw content, and processes it in background workers.

Those workers classify and summarize findings, extract IOCs and named entities, and write relationships into a graph. The dashboard exposes the resulting findings, briefs and correlations.

**Show:** Stay on `/presentation`. Point at `raw signals → processed → entities + IOCs → correlation candidate`.

### 00:55–01:20 — The interesting part

**Say:**

The interesting part was not collecting a lot of messages. It was finding a relationship useful enough for a person to check.

One rumor may be weak. Another source can give it context. A shared IOC, a reused handle, or two signals close in time can become a correlation path.

There were a few times when something appeared in my Noctis brief before I personally saw it discussed more widely. I remember that happening with Dirty Frag in the Linux kernel. That is my personal anecdote, not a benchmark or a prediction claim.

**Show:** `/presentation/brief`, then click **Trace the correlation path** to `/presentation/correlation`. The path on screen is synthetic.

### 01:20–01:48 — How the system works

**Say:**

The repository documents five layers: collectors, ingest, background processing, the intelligence brain, and infrastructure plus the dashboard.

The correlator starts with deterministic rules for shared IOCs, handle reuse, temporal overlap and entity clusters. An LLM analyst can then promote, reject or defer a candidate while keeping the reasoning and context snapshot.

**Show:** `/presentation/architecture`. Move left to right across the five layers, then point to the loop ending in human verification.

### 01:48–02:15 — What failed and what I learned

**Say:**

The weak point eventually became the basic AI processing layer. Classification, summarization and IOC extraction used Llama 4 Scout, and I still saw roughly twenty to twenty-five percent of noise getting through. That is my operating estimate, not a benchmark.

I did not want to stack features on top of that. The documented rebuild direction starts with label validation, a clean dataset, consistent IOC masking and a measurable two-stage baseline, before returning to a more specialized agent.

I paused because I needed distance and moved to another project. I still want to return to the same question: how far can collection and correlation be automated while every important conclusion stays understandable and verifiable?

**Show:** `/presentation/lessons`. End on the green “What I want to return to” callout.

## Short form context

Noctis is a self-hosted threat-intelligence daemon I built out of curiosity about how signals from underground communities, infrastructure and vulnerabilities can be connected. This short demo shows the real architecture, a synthetic finding path, and the rebuild lessons that made me pause the project.

## AI-use disclosure

I used AI during Noctis development for coding and research. For this presentation, I also used it to help structure the story and build the isolated presentation view. The project, experiments, operating observations and conclusions shown here come from my own work with Noctis.

## Recording notes

- Keep the browser at **1920×1080** (Chrome or Chromium recommended).
- Start at `http://127.0.0.1:5173/presentation`.
- Follow: **Overview → Brief → Correlation → Architecture → Lessons / rebuild**.
- Use the visible bottom-right action buttons or the keyboard **Right Arrow**. The **Left Arrow** moves back.
- The Dirty Frag reference is spoken as a personal anecdote only; no screen claims to contain that event.
