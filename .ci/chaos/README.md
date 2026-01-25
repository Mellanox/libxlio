# CI Chaos Testing

This directory contains chaos testing for validating CI pipeline correctness.

## Adding a New Chaos Patch

**Two simple steps:**
1. Add a `.diff` file to `patches/`
2. Add an entry to `chaos_config.yaml`

---

## Configuration Format

The `chaos_config.yaml` file maps patches to expected failures:

```yaml
patches:
  # One patch breaks one step
  - file: style_violation.diff
    expect_fail:
      - step: Style

  # One patch can break multiple steps
  - file: build_error.diff
    expect_fail:
      - step: Build
      - step: Package
```

**Note:** Step names must exactly match the names in `matrix_job.yaml` (case-sensitive).

---

## How It Works

### On Every PR

The **"Verify Chaos Patches"** step validates:
1. All files listed in `chaos_config.yaml` exist in `patches/`
2. All patches apply cleanly (`git apply --check`)

### Weekly Chaos Run (Saturday 2:00 AM)

1. Chaos launcher triggers main CI with `do_chaos=true`
2. For each step, `run_step.sh`:
   - **Has patches** → Applies patches, runs step, resets code, records failure
   - **No patches** → Runs step normally
3. Results compared against `chaos_config.yaml`
4. Email report sent with pass/fail status

---

## Directory Structure

```
.ci/
├── scripts/
│   └── run_step.sh                 # Applies per-step patches in chaos mode
└── chaos/
    ├── patches/                    # Chaos patch files
    ├── chaos_config.yaml           # Maps patches to expected failing steps
    ├── chaos_launcher_jjb.yaml     # Chaos job definition
    ├── chaos_matrix_job.yaml       # Chaos job config file
    └── README.md                   # This file
```
