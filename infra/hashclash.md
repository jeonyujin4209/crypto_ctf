# HashClash (MD5 collision toolkit) — CUDA Docker build

Marc Stevens' HashClash provides the only practical MD5 chosen-prefix
collision (CPC) generator. CryptoHack's **Twin Keys** and related
MD5-collision challenges need it. HashClash has optional CUDA
acceleration that gives a ~10-100× speedup on the dominant birthday
search phase, turning a ~4-8 hour CPC run into ~30-60 min on a consumer
NVIDIA GPU.

This doc records the Dockerfile + run pattern that actually works on a
Windows 11 host with Docker Desktop + WSL2 + NVIDIA Container Toolkit.

## Prerequisites

- NVIDIA GPU with CUDA compute capability ≥ 6.0 (any Pascal or later)
- NVIDIA driver ≥ 525 (check `nvidia-smi` on the host)
- Docker Desktop with **WSL2 backend** + **Use WSL2 based engine** enabled
- NVIDIA Container Toolkit installed (Docker Desktop auto-installs this
  when GPU support is enabled in Settings → Resources → WSL Integration)

Verify once before building:

```bash
docker run --rm --gpus all nvidia/cuda:12.6.0-base-ubuntu22.04 nvidia-smi
```

If this shows your GPU, passthrough works. If not, enable GPU support
in Docker Desktop settings and restart the engine.

## Build

The Dockerfile is at `infra/Dockerfile.hashclash`:

```bash
cd crypto_ctf
docker build -t hashclash -f infra/Dockerfile.hashclash infra/
```

Expected build time: ~3-5 minutes (dominated by boost 1.88.0 compile).
Image size: ~2 GB.

### Key Dockerfile choices (and why)

- **Base image**: `nvidia/cuda:12.6.0-devel-ubuntu22.04` — `devel` variant
  is mandatory (needs `nvcc` + CUDA headers). `base` and `runtime`
  variants don't have them.
- **apt deps**: `git ca-certificates build-essential autoconf automake
  libtool pkg-config libboost-all-dev zlib1g-dev libbz2-dev wget`
  - `libbz2-dev` is easy to miss — HashClash's `build.sh` silently
    builds boost without bzip2 support if absent, and some HashClash
    tools then fail at runtime.
  - `wget` is required because HashClash's `install_boost.sh` downloads
    the boost tarball with wget (not curl).
- **Boost**: Let HashClash build its own pinned boost 1.88.0 via
  `install_boost.sh`. Don't try to use system boost (HashClash autoconf
  is picky about boost version and tends to fail on the system package).
- **CUDA flag**: patch `build.sh` to pass `--with-cuda=/usr/local/cuda`
  to configure, since the upstream script doesn't forward it:
  ```
  sed -i 's|./configure --with-boost=${BOOST_INSTALL_PREFIX}|./configure --with-boost=${BOOST_INSTALL_PREFIX} --with-cuda=/usr/local/cuda|' build.sh
  ```
- **Build verification**: check that `md5_birthdaysearch` is dynamically
  linked against `libcudart.so.12`:
  ```
  ldd /hashclash/bin/md5_birthdaysearch | grep cuda
  ```
  If you see `libcudart.so.12 => ...` the build is GPU-capable. If not,
  CUDA wasn't picked up during configure — inspect `config.log`.
- **Binary list**: current upstream produces
  `md5_birthdaysearch, md5_diffpathbackward, md5_diffpathconnect,
  md5_diffpathforward, md5_diffpathhelper, md5_fastcoll, md5_textcoll`
  plus the SHA-1 equivalents. An older README referenced
  `md5_diffpathconstruction` which no longer exists — don't fail the
  build checking for it.

## Run

**The `--gpus all` flag is mandatory**. Without it, the binaries still
load but silently fall back to CPU code paths:

```bash
REPO='C:\\Users\\UserK\\Documents\\hackerone\\program\\crypto_ctf'
MSYS_NO_PATHCONV=1 docker run --rm --gpus all \
    -v "${REPO}:/work" \
    -w "/work/path/to/problem/hashclash_work" \
    hashclash \
    /hashclash/scripts/fastcpc.sh prefix1.bin prefix2.bin
```

`MSYS_NO_PATHCONV=1` prevents git-bash from rewriting `/work/...` into
`C:/Program Files/Git/work/...`. Same gotcha as the sagemath wrapper —
see `infra/sage-run.sh`.

The work directory (`-w` path) must contain `prefix1.bin` and
`prefix2.bin`, the two arbitrary byte-prefixes you want to find a CPC
between. HashClash writes its intermediate state and final output files
to the current directory, so mount a dedicated folder per problem to
avoid mess.

### Monitoring GPU utilization mid-run

```bash
watch -n 2 nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv
```

GPU usage is **zero during the precompute phase** (differential path
construction is CPU-bound) and jumps to ~90-100% during the birthday
search and near-collision phases. If you reach the birthday phase and
GPU util stays low, something is wrong with the passthrough.

## Phase timing (reference: RTX 4060 Ti, Docker Desktop WSL2)

- **Precompute** (builds ~10 differential paths, CPU-bound): ~1-2 min
  per path, total ~15-20 min. Single-threaded.
- **Birthday search**: GPU-heavy. On RTX 4060 Ti: ~minutes per block.
  CPU only: ~30-60 min per block.
- **Near-collision blocks**: up to `MAXBLOCKS=7`. GPU: minutes each.
  CPU: hours each.
- **End-to-end CPC**:
  - CPU only: 4-8 hours
  - RTX 4060 Ti via Docker: 30-90 minutes (dominated by precompute +
    a few birthday-phase restarts)

## Tuning knobs in `fastcpc.sh`

Pass as environment variables or edit the script:

- `BLOCK_TIMEOUT=2000` (seconds). Lower to ~900 for faster fail-retry
  on a fast GPU.
- `MAXBLOCKS=7`. Leave alone — this is the max number of NC blocks.
- `HYBRIDBITS=0`. Bumping to 4-6 may speed up some prefix pairs.
- `BIRTHDAY_LOCAL_CONFIG="--cuda_enable ..."` — already on by default
  when CUDA is detected at build time.

## Relation to other MD5 tools

- **`fastcoll_v1.0.0.5.exe`** — standalone Windows binary from Marc
  Stevens for **identical-prefix** collisions (IPC). Seconds per pair,
  no GPU needed, no build required. Download:
  <https://marc-stevens.nl/research/hashclash/fastcoll_v1.0.0.5.exe.zip>
  → extract to `~/AppData/Local/Temp/fastcoll/` (matches paths in some
  solvers). Use this for problems like PriMeD5.
- **HashClash CUDA Docker** (this doc) — heavy **chosen-prefix**
  generator. Use for problems like Twin Keys.

## Troubleshooting

- *"Error response from daemon: could not select device driver"* —
  NVIDIA Container Toolkit isn't installed / WSL2 GPU support disabled
  in Docker Desktop.
- *CUDA not linked* (no `libcudart` in `ldd` output) — `--with-cuda`
  flag didn't reach configure, or `nvcc` wasn't on PATH during build.
  Re-check the sed patch in the Dockerfile.
- *fastcpc runs forever on a single NC block* — probably stuck on a
  hard differential path. Lower `BLOCK_TIMEOUT` so it retries sooner.
- *`invalid working directory` on `docker run`* — add
  `MSYS_NO_PATHCONV=1` in front of the docker invocation when running
  from git-bash.
