# Turning on the merge queue and required checks: report

Written 2026-11-26 for the decision to change the `main` ruleset. Nothing described here has been turned on: the ruleset in the appendix was read before and after Slices 7 and 8 and is unchanged. Every number below is labelled with the run it came from.

## Merge queue

**Available:** yes. The repository is public, and a merge queue is a ruleset rule on `main`.

**Proposed ruleset** (an update to ruleset `main`, id 27031502). It keeps the existing rules (no deletion, no force push, one approval, squash only) and adds required checks and a merge queue:

```json
{
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request", "parameters": {"required_approving_review_count": 1, "dismiss_stale_reviews_on_push": false, "require_code_owner_review": false, "require_last_push_approval": false, "required_review_thread_resolution": false, "allowed_merge_methods": ["squash"]}},
    {"type": "required_status_checks", "parameters": {"strict_required_status_checks_policy": false, "required_status_checks": [
      {"context": "tier1"},
      {"context": "tier2-e2e"},
      {"context": "tier2-policy (v1.30.13)"},
      {"context": "tier2-policy (v1.32.11)"},
      {"context": "tier2-policy (v1.34.3)"},
      {"context": "tier3"}
    ]}},
    {"type": "merge_queue", "parameters": {"merge_method": "SQUASH", "max_entries_to_build": 2, "min_entries_to_merge": 1, "max_entries_to_merge": 5, "min_entries_to_merge_wait_minutes": 5, "grouping_strategy": "ALLGREEN", "check_response_timeout_minutes": 60}}
  ]
}
```

- **Checks:** the five Tier 1 and Tier 2 checks, which run on `pull_request` and `merge_group`, and `tier3`. `tier3` reports skipped on pull requests. In the merge queue it passes with a skip note (unless the gate itself cannot reach the GitHub API, see the risks under Tier 3) until a NIC release contains nebari-infrastructure-core#787, and then it deploys and blocks by itself (no ruleset change needed at that point). GitHub requires `merge_group` triggers for every required check, or the queue waits for a check that never reports ([managing a merge queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue#triggering-merge-group-checks-with-github-actions)); `ci.yml` and `journeys.yml` both have it.
- **Build concurrency 2, group size 1 to 5, 5-minute wait:** from the throughput section below.
- **`ALLGREEN`** ("only merge non-failing pull requests"): every PR in a group must pass, so one bad PR does not ride in on a passing group.
- **Check timeout 60 minutes:** above Tier 3's 90-minute job limit would be safer once Tier 3 runs in the queue; 60 covers every measured run (the slowest Tier 3 job was 29 min 6 s, the failed NIC deploy below). Revisit when Tier 3 starts blocking.

## Stacking

The open work is a chain of plain PRs: #1 targets `main`, and each later PR targets the branch before it (#2 on #1's branch, through #8 on #7's).

- GitHub retargets a stacked PR when the head branch of the PR below it is deleted after merging: it "checks for any open pull requests in the same repository that specify the deleted branch as their base branch" and changes "their base branch to the merged pull request's base branch" ([merging a pull request](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/merging-a-pull-request#about-pull-request-merges)). This repository has `delete_branch_on_merge` set to `false`, so after #1 merges someone deletes `docs/user-secrets-design` (or the setting is turned on) and #2 moves to `main`.
- `main` allows squash only. After #1 is squashed, #2's branch still carries #1's original commits, so #2 retargeted to `main` shows #1's changes again until it is rebased: `git rebase --onto main docs/user-secrets-design feat/us-01-sealing`, then force-push. Each later PR needs the same step when the one below it merges.
- With a merge queue, each PR enters the queue only after its retarget and rebase, so the stack merges one PR at a time, in order.

To be observed at the first stack merge: the retarget after deleting the merged branch, and how the queue handles a PR whose base was just squashed. Neither was measured here. Proposal: turn on `delete_branch_on_merge` together with the queue, so the retarget happens without a manual step.

## Tier 3 time and size

Both runs below ran on short-lived scratch branches that were deleted afterwards. A `workflow_dispatch` run needs the workflow on the default branch, and `journeys.yml` is not there yet, so each scratch branch added a `push` trigger for itself. The release run's branch changed nothing else. The proof run's branch also replaced the gate step with fixed outputs: NIC `de81b11`, blocking.

Tier 3 runs on `ubuntu-latest`. The deploy step is `nebari-dev/deploy-nebari-action@v0.3.0`, which replaced `action-nebari-sandbox` v3.0.0 during this slice (the sandbox cannot deploy NIC v0.15.0 or later: it waits for a MetalLB namespace NIC no longer creates).

**Proof run on the #787 merge commit (`de81b11`), full run with the journeys.** Run [45651421474](https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45651421474), attempt 2, 2026-11-25. Step durations from the jobs API:

| Phase | Seconds |
|---|---|
| Deploy Nebari (fetch and build NIC at the sha, `nic deploy`, the action's convergence wait) | 489 |
| Build the image and load it into the cluster | 73 |
| Seed Keycloak | 1 |
| Prepare the install | 0 |
| Register the chart | 19 |
| Register the cluster bundle | 24 |
| Platform convergence | 11 |
| Journeys (`TestChartConvergesOnNebari`, `TestManagementOnNebari`) | 37 |
| Whole job | 686 (11 min 26 s) |

**Latest release run (`v0.18.0`, the gate's choice), platform bring-up up to our install.** Run [45796258597](https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45796258597), 2026-11-26, job 20 min 39 s. The gate chose `v0.18.0` (`dfae9f2`) and decided `NON-BLOCKING`. NIC deployed and our chart registered and synced, then `user-secrets` stayed `Synced`/`Degraded`: `v0.18.0` has no `nebari-ca-issuer`, so the serving certificate is never issued. The job ended with the warning "Tier 3 failed (NON-BLOCKING until a NIC release contains #787): converge journeys" and exited 0, as designed. Phase times from the workflow's own timing step:

| Phase | Seconds |
|---|---|
| deploy (download NIC `v0.18.0`, `nic deploy`, the action's convergence wait) | 296 |
| image | 85 |
| seed | 1 |
| prepare | 0 |
| register-chart | 22 |
| register-cluster | 22 |
| converge (ran to its 10-minute limit: our chart cannot become Healthy on `v0.18.0`) | 605 |
| journeys (failing against the unready service) | 168 |

Platform bring-up up to our install is the first six rows: 426 s, about 7 minutes. A release download is faster than the proof run's source build (296 s against 489 s for the deploy step).

**Other Tier 3 runs on the deploy action, for variance:**

| Run | NIC | Result | Job time |
|---|---|---|---|
| [45643916686](https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45643916686) | `de81b11` | convergence check failed (required NIC's own Applications to be Synced; fixed) | 21 min 7 s |
| [45649868264](https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45649868264) | `de81b11` | both journeys passed; job failed on a Tier 1 test the step should not have run (fixed) | 11 min 12 s |
| [45651421474](https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45651421474) attempt 1 | `de81b11` | NIC's own deploy failed: "Failed to install Argo CD: context deadline exceeded" | 29 min 6 s |
| [45651421474](https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45651421474) attempt 2 | `de81b11` | green | 11 min 26 s |

One of five NIC deploys on the deploy action (the four runs above and the release run) failed inside NIC's Argo CD install, before any of our steps. That is a small sample, but it is the main risk of making `tier3` blocking: a platform failure would remove a good PR from the queue.

The second risk is the gate itself. Its step has no `continue-on-error`, so if the GitHub API cannot answer which NIC release is latest, `tier3` fails in every mode, including in the merge queue while Tier 3 is meant to be non-blocking. That is deliberate: Tier 3 never guesses whether it should block. To make a short API outage unlikely to remove a group, the gate retries for about two minutes (6 attempts, 5 to 25 s apart) before failing.

## Queue throughput

Measured job times (PR #8, run [45629281918](https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45629281918)): `tier1` 3 min 25 s, `tier2-e2e` 8 min 3 s, `tier2-policy` 1 min 28 s to 1 min 46 s. Tier 3 full run: about 11.5 minutes (proof run above).

A group's checks run in parallel, so a group takes max(Tier 2, Tier 3), and with build concurrency C the queue finishes at most C groups per that time.

- **Now, while Tier 3 skips in the queue:** a group takes about 8 minutes (`tier2-e2e`). With C = 2 that is up to 15 groups an hour.
- **Once Tier 3 blocks:** about 12 minutes a group, up to 10 groups an hour with C = 2.
- **A typical day here** is a handful of merges (this repository's history: one stack of eight PRs over a week). With groups of up to 5, a day's merges fit in one or two groups, well under an hour.
- **A failing group** costs one more group run: GitHub removes the failing PR and rebuilds the next PR's group without it ([failing CI](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue#failing-ci)). That is about 8 minutes now, 12 once Tier 3 blocks, plus 11.5 more for every Tier 3 platform failure.

## Runner fit

`ubuntu-latest` for public repositories: 4 vCPU and 16 GB memory. The CI spec assumed 14 GB of free disk; the runner measured below had far more.

From the release run's resource step (run 45796258597), a snapshot after the journeys, not a peak:

```
               total        used        free      shared  buff/cache   available
Mem:           15983        4080        1051          94       11291       11903
Filesystem      Size  Used Avail Use% Mounted on
/dev/root       145G   68G   78G  47% /
```

Node `us-journeys-control-plane` (the single kind node, on the runner): allocatable 4 CPU and 16366628Ki memory; pod requests 2390m CPU (59%) and 4194Mi memory (26%); limits 6050m CPU (151%) and 10246Mi memory (64%).

- **Memory fits:** about 4 GB used and 11.9 GB available of 16 GB at the snapshot. Limits are below the node's memory, so even every pod at its limit (10 GB) fits.
- **CPU is overcommitted on limits** (151%), as is normal for kind; requests are at 59%, so scheduling fits. CPU contention is the likely cause of slow phases, and possibly of the one failed Argo CD install above.
- **Disk fits with room:** the runner's root filesystem reported 145 GB with 78 GB free, more than the 14 GB the CI spec assumed. GitHub's runner image determines this; the 14 GB figure in the spec is out of date for this runner.
- **Not measured:** the peak during the deploy. The step records one snapshot at the end. If the queue later shows memory trouble, sampling during the deploy is the next measurement.

Tier 3 fits the standard runner; no larger runner is needed.

## Appendix: the ruleset, unchanged

Read with `gh api repos/nebari-dev/nebari-user-secrets/rulesets` and `gh api repos/nebari-dev/nebari-user-secrets/rulesets/27031502` before Slice 8's work started (2026-11-25) and again on 2026-11-26; the two reads are identical.

```json
{
  "id": 27031502,
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "exclude": [],
      "include": [
        "~DEFAULT_BRANCH"
      ]
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": false,
        "required_reviewers": [],
        "require_code_owner_review": false,
        "dismissal_restriction": {
          "enabled": false,
          "allowed_actors": []
        },
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "require_extra_approval_for_unattributed_changes": true,
        "allowed_merge_methods": [
          "squash"
        ]
      }
    }
  ],
  "bypass_actors": [
    {
      "actor_id": null,
      "actor_type": "OrganizationAdmin",
      "bypass_mode": "always"
    }
  ]
}
```
