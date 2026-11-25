# Grokbot-clon Offline Deployment & N3 Verification Runbook

## 1. Honest Platform Scope (`N1`/`N2` vs `PENDING_N3_LINUX_ENV`)
- **macOS (`Darwin`)**: N1 (unit) and N2 (Playwright + local loopback lab apps + SQLite WAL + local HTTP mock LLM) checks are executed natively.
- **Linux Target (`N3`)**: Kernel network namespace / `nftables` / `iptables` outbound-blocking (`A11`), real local LLM weights (`ollama` / `llama-server` / `vllm`), `systemd` (`deploy/grokbot.service`), rootless `Containerfile`, and live AT-SPI/X11/Wayland desktop probes remain **`PENDING_N3_LINUX_ENV`** until executed on a Linux host.

---

## 2. Offline Artifact Staging (Zero Internet Access at Install Time)
Prepare the offline bundle on a build machine before transferring to the air-gapped Linux pilot host:
1. **Python Wheelhouse**:
   ```bash
   uv export --frozen --no-dev -o requirements.txt
   pip download --dest /opt/grokbot/wheelhouse -r requirements.txt
   ```
2. **Playwright Chromium Binary (`chromium-1248`) & Notices**:
   - Stage cached `chromium-1248` and `chromium_headless_shell-1248` into `/opt/grokbot/ms-playwright`.
   - Preserve Chromium `LICENSE` (`BSD-3-Clause`) and document whether optional `ffmpeg-1013` (`LGPL-2.1+`) is included or excluded (see `THIRD_PARTY_NOTICES.md`).
3. **Local LLM Weights**:
   - Stage pinned GGUF/quantized model weights (e.g. `qwen2.5-7b-instruct` `Q4_K_M`) and record their SHA-256 in `deploy/install_config.yaml` (`local_model.weights_sha256`).

---

## 3. Validate Declarative Install Config
```bash
uv run python -m deploy.config --config deploy/install_config.yaml --json
```
- **Fail-closed guarantees**: rejects empty `allowed_origins`, wildcard `0.0.0.0`, external internet URLs/IPs, `allow_external_egress: true`, `egress_blocked: false`, `factory_isolated: false`, or facility apps absent from `allowed_origins`.
- **Expected Exit Code**: `0` on valid config, `1` with `stderr` diagnostic on invalid config.

---

## 4. Release Packaging & State-Preserving Rollback
### Package a Release Manifest
```bash
uv run python -m deploy.package \
  --config deploy/install_config.yaml \
  --output /var/lib/grokbot/releases/v0.1.0/manifest.json \
  --releases-dir /var/lib/grokbot/releases \
  --version 0.1.0 \
  --json
```
- Records SHA-256 checksums for `pyproject.toml`, `uv.lock`, `deploy/`, `lab/configs/`, and `src/`, links `previous_release_id`, records `state_preserve_paths` (`sqlite_wal_path` and `profile_root`), and stamps honest `n3_status`.

### State-Preserving Rollback
```bash
uv run python -m deploy.rollback \
  --releases-dir /var/lib/grokbot/releases \
  --target-release rel-0.1.0 \
  --root-dir /opt/grokbot/app \
  --json
```
- Verifies artifact SHA-256 digests against `--root-dir`.
- **Preserves** existing SQLite WAL files (`grokbot.sqlite3`, `-wal`, `-shm`) and Playwright `profile_root` directories untouched.
- Atomically switches `current_release.json` and appends an audit entry to `rollback_history.jsonl`.
- On missing/corrupt manifest or checksum mismatch, prints a clean diagnostic to `stderr` and exits `1` (without `argparse` usage output).

---

## 5. Linux Outbound-Blocked Network Isolation (`A11` / N3)
On the target Linux host (as root / network admin):
1. Create an isolated network namespace or `nftables`/`iptables` `OUTPUT` policy allowing loopback (`127.0.0.1/8`) and configured local LAN subnets only, while dropping all external egress:
   ```bash
   sudo ip netns add grokbot_offline
   sudo ip netns exec grokbot_offline ip link set lo up
   # Example nftables/iptables OUTPUT drop for non-loopback / non-LAN:
   sudo iptables -P OUTPUT DROP
   sudo iptables -A OUTPUT -o lo -j ACCEPT
   ```
2. Start the local LLM server (`ollama` or `llama-server` on `127.0.0.1:8080`).
3. Run the N3 verification script inside the isolated Linux environment:
   ```bash
   ./scripts/verify_n3_linux.sh
   ```
   Expected exit code: `0` on compliant Linux host with active local LLM; `1` with `[PENDING_N3_LINUX_ENV]` on macOS or missing Linux prerequisites.
