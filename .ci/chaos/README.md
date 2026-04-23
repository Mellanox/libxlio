# Chaos testing

Chaos testing verifies that CI checks actually catch the violations they are
meant to catch. The weekly [LibXLIO-opensource-chaos](https://nbuprod.blsm.nvidia.com/swx-media-master/job/libxlio/job/LibXLIO-opensource-chaos/) Jenkins job triggers
the main CI in chaos mode, which applies the patches under `patches/` to the
source tree before running each step. If a step that is expected to fail
passes instead, the chaos job fails and posts the result to the
[Libxlio Chaos Testing Builds](https://teams.microsoft.com/l/team/19%3Ah3O6RitjzlNHp8cLHH1J49JydpsJqpHQmS66BO5hqiY1%40thread.tacv2/conversations?groupId=ecfa4fbd-630c-42a5-a945-0925eb354486&tenantId=43083d15-7273-40c1-b7db-39efd9ccc17a)
Teams channel.

## `chaos_config` format

One line per patch, mapping it to the CI step names it is expected to break.
Step names are comma-separated and may contain spaces:

    patch_file.diff: StepName1, Step Name 2, ...

**Step names must match the `name:` field of the step in `.ci/matrix_job.yaml`.**
Patch paths are relative to `patches/`. Only the `do_*` flags for the listed
steps are enabled in the chaos run.

## Adding a new chaos patch

1. **Create the diff.** Generate a patch that breaks the step you want to
    test, and save it as `patches/<name>.diff`. It must apply
   cleanly against the current tree (`git apply --check`).

2. **Register it in `chaos_config`.** Add a line naming the patch and the
   step(s) it should break:

       <name>.diff: Style

3. **Wire the target step (if not already chaos-aware).** In
   `.ci/matrix_job.yaml`, prefix the step's `run:` command with the chaos
   wrapper when `do_chaos` is on:

         run: |
           $([ "${do_chaos}" = "true" ] && echo "$CHAOS_WRAPPER <StepName>") \
           <original command>

   In normal builds the `$(...)` expands to an empty string and the step runs
   unchanged. Under chaos, the wrapper applies the patches and inverts the exit
   code - a step that fails as expected reports success, and one that unexpectedly
   passes reports failure.

4. **Open a PR.** The main CI's *Verify Chaos Patches* step confirms the
   diff still applies cleanly on every PR build. The next weekly chaos run
   confirms the target step actually catches the violation.

## Keeping patches healthy

Patches are static diffs against the live source tree, so they break when the
files they touch change. *Verify Chaos Patches* step runs on every PR and
will fail with the offending `*.rej` archived as a build artifact. When that
happens, regenerate the diff against the current source and update it.

## Layout

    .ci/chaos/
    ├── chaos_config        # patch -> steps mapping
    ├── patches/            # *.diff files applied during chaos runs
    └── README.md

Related files outside this directory:

- `.ci/scripts/run_chaos_step.sh` — wrapper that applies patches, runs the
  real step, reverts, and records failures
- `.ci/pipeline/chaos_matrix_job.yaml` — the chaos launcher pipeline
- `.ci/matrix_job.yaml` — main CI; contains the *Verify Chaos Patches* step
  and the chaos wiring on individual steps
