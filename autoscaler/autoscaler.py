#!/usr/bin/env python3
"""
Proxy autoscaler.

Every CHECK_INTERVAL seconds it reads Docker memory stats for every running
proxy replica.  When the *maximum* per-replica usage exceeds SCALE_UP_PCT it
adds one replica (up to MAX_REPLICAS).  When the *average* drops below
SCALE_DOWN_PCT it removes one replica (down to MIN_REPLICAS).

Scale-up  → docker compose --no-recreate (safe, touches nothing running)
Scale-down → stop + remove the least-loaded replica directly via Docker SDK
             (avoids docker compose accidentally recreating stopped containers)
"""

import docker
import subprocess
import time
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

PROJECT_NAME   = os.getenv("COMPOSE_PROJECT_NAME", "proxygpt")
SERVICE_NAME   = "proxy"
COMPOSE_FILE   = "/compose/docker-compose.yml"

MIN_REPLICAS   = int(os.getenv("MIN_REPLICAS",   "2"))
MAX_REPLICAS   = int(os.getenv("MAX_REPLICAS",   "10"))
SCALE_UP_PCT   = float(os.getenv("SCALE_UP_PCT",   "70"))  # max replica mem % → add one
SCALE_DOWN_PCT = float(os.getenv("SCALE_DOWN_PCT", "30"))  # avg replica mem % → remove one
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL",   "30"))  # seconds between checks
COOLDOWN       = int(os.getenv("COOLDOWN",        "120"))  # seconds between scale actions

client       = docker.from_env()
last_scale_at = 0.0


def proxy_containers():
    return client.containers.list(filters={
        "label": [
            f"com.docker.compose.project={PROJECT_NAME}",
            f"com.docker.compose.service={SERVICE_NAME}",
        ],
        "status": "running",
    })


def mem_pct(container) -> float | None:
    """Return memory usage as % of the container's limit (cache excluded)."""
    try:
        s    = container.stats(stream=False)
        mem  = s["memory_stats"]
        used = mem["usage"] - mem.get("stats", {}).get("cache", 0)
        lim  = mem["limit"]
        return (used / lim) * 100
    except Exception as e:
        log.warning("Could not read stats for %s: %s", container.name, e)
        return None


def scale_up(current: int):
    global last_scale_at
    target = current + 1
    log.info("Scaling UP: %d → %d replicas", current, target)
    result = subprocess.run(
        [
            "docker", "compose",
            "-p", PROJECT_NAME,
            "-f", COMPOSE_FILE,
            "up", "--scale", f"{SERVICE_NAME}={target}",
            "--no-recreate", "-d",
        ],
        capture_output=True, text=True, timeout=90,
    )
    if result.returncode == 0:
        log.info("Scale-up to %d succeeded.", target)
        last_scale_at = time.time()
    else:
        log.error("Scale-up failed (rc=%d): %s", result.returncode, result.stderr.strip())


def scale_down(containers: list):
    global last_scale_at
    # Stop the least-loaded replica to minimise disruption
    with_mem = [(c, mem_pct(c) or 100.0) for c in containers]
    with_mem.sort(key=lambda x: x[1])
    victim, victim_mem = with_mem[0]
    log.info(
        "Scaling DOWN: stopping least-loaded replica %s (%.1f%% mem)",
        victim.name, victim_mem,
    )
    try:
        victim.stop(timeout=30)
        victim.remove()
        log.info("Replica %s stopped and removed.", victim.name)
        last_scale_at = time.time()
    except Exception as e:
        log.error("Scale-down failed for %s: %s", victim.name, e)


def main():
    log.info(
        "Autoscaler started | project=%s  service=%s  "
        "replicas=[%d..%d]  scale_up>%.0f%%  scale_down<%.0f%%  "
        "interval=%ds  cooldown=%ds",
        PROJECT_NAME, SERVICE_NAME,
        MIN_REPLICAS, MAX_REPLICAS,
        SCALE_UP_PCT, SCALE_DOWN_PCT,
        CHECK_INTERVAL, COOLDOWN,
    )

    while True:
        time.sleep(CHECK_INTERVAL)
        try:
            containers = proxy_containers()
            current    = len(containers)
            if current == 0:
                log.warning("No running proxy containers found — skipping.")
                continue

            pcts = [p for p in (mem_pct(c) for c in containers) if p is not None]
            if not pcts:
                continue

            avg = sum(pcts) / len(pcts)
            mx  = max(pcts)
            log.info("replicas=%d  avg_mem=%.1f%%  max_mem=%.1f%%", current, avg, mx)

            if (time.time() - last_scale_at) < COOLDOWN:
                log.info("In cooldown (%.0fs remaining) — skipping.", COOLDOWN - (time.time() - last_scale_at))
                continue

            if mx >= SCALE_UP_PCT and current < MAX_REPLICAS:
                log.info("Max mem %.1f%% ≥ scale-up threshold %.0f%%", mx, SCALE_UP_PCT)
                scale_up(current)
            elif avg <= SCALE_DOWN_PCT and current > MIN_REPLICAS:
                log.info("Avg mem %.1f%% ≤ scale-down threshold %.0f%%", avg, SCALE_DOWN_PCT)
                scale_down(containers)

        except Exception:
            log.exception("Autoscaler loop error")


if __name__ == "__main__":
    main()
