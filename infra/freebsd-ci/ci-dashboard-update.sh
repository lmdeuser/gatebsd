#!/bin/sh
# Publish a read-only CI/CD dashboard describing pipeline runs, their jobs, the
# logs those jobs produced, and the release artifacts they published.
#
# Why this exists
# ---------------
# Every part of the pipeline already worked before this script: runs execute,
# packages get signed, releases land under a stable URL. None of it was
# *visible*. Forgejo's own Actions UI answers "what did run 12 do", but it
# redirects anonymous visitors to /forgejo/user/login (anonymous repository
# access is deliberately disabled because the runner executes on the host with
# no container isolation), and its job-level REST endpoint is not served by this
# Forgejo version -- /actions/runs/<n>/jobs returns 404. So the only way to see
# a job was to log in, and the only way to find a build artifact was to read a
# job log for a build ID nobody could derive.
#
# This generator closes that gap without weakening the trust boundary: it reads
# Forgejo's database *read-only* and renders static files. Nothing here can
# mutate a run, cancel a job, or expose a repository that Forgejo is keeping
# private. It publishes exactly three things -- run/job status, job logs, and
# artifact locations -- to a LAN-only nginx vhost.
#
# Output (all atomically renamed into place):
#   <OUT>/index.html      operator-facing dashboard
#   <OUT>/status.json     same data, machine-readable
#   <OUT>/logs/<id>.txt   decompressed job logs
set -eu

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

FORGEJO_DB=${FORGEJO_DB:-/var/db/forgejo/forgejo.db}
ACTIONS_LOG_ROOT=${ACTIONS_LOG_ROOT:-/var/db/forgejo/data/actions_log}
# The mirror tree is rooted at the project slug rather than at one product's
# name. Default `gatebsd` leaves every path and link exactly as published today.
# `-` and not `:-`: an explicitly empty PROJECT_SLUG means a caller computed
# one and came back with nothing, and defaulting there would publish a second
# product under this one's root. Only an unset variable asks for the default.
PROJECT_SLUG=${PROJECT_SLUG-gatebsd}
case "$PROJECT_SLUG" in
    ''|*[!a-z0-9-]*)
        echo "PROJECT_SLUG must be non-empty and match [a-z0-9-]: $PROJECT_SLUG" >&2
        exit 2 ;;
esac
RELEASE_ROOT=${RELEASE_ROOT:-/tank/${PROJECT_SLUG}/releases}
ARTIFACT_ROOT=${ARTIFACT_ROOT:-/tank/ci/artifacts}
STATUS_DIR=${STATUS_DIR:-/tank/mirror/status}
OUT_DIR=${OUT_DIR:-/tank/mirror/www/ci}
TEMPLATE_DIR=${TEMPLATE_DIR:-/usr/local/share/gatebsd-ci}
BASE_URL=${BASE_URL:-http://mirror.example.lan}
FORGE_URL=${FORGE_URL:-https://git.example.lan/forgejo}
REPO_SLUG=${REPO_SLUG:-owner/gatebsd}
case "$REPO_SLUG" in
    */*) ;;
    *)
        echo "REPO_SLUG must be owner/repo: $REPO_SLUG" >&2
        exit 2 ;;
esac
case "${REPO_SLUG%%/*}" in
    ''|*[!A-Za-z0-9._-]*)
        echo "Invalid repository owner in REPO_SLUG: $REPO_SLUG" >&2
        exit 2 ;;
esac
case "${REPO_SLUG#*/}" in
    ''|*/*|*[!A-Za-z0-9._-]*)
        echo "Invalid repository name in REPO_SLUG: $REPO_SLUG" >&2
        exit 2 ;;
esac
# Runs shown. The dashboard is a status page, not an archive; Forgejo keeps the
# full history and is one click away.
RUN_LIMIT=${RUN_LIMIT:-25}
# Logs are published for this many of the most recent runs only. A log is the
# largest thing here and the oldest ones are the least interesting.
LOG_RUNS=${LOG_RUNS:-10}
# A job log is operator-facing output, not a data feed. Anything past this is
# almost certainly a runaway loop, and publishing it unbounded would let one bad
# job fill the web root.
LOG_MAX_BYTES=${LOG_MAX_BYTES:-2097152}

# No `id -u` check here. In production this runs from cron as root because the
# Forgejo database is root-owned and the web root is root-owned, but "am I root"
# is a proxy for the two things that actually matter, and both are checked
# directly: the database must be readable (below) and the output tree must be
# writable (the publication step fails loudly if it is not). Testing the real
# requirements instead of the proxy also lets this run unprivileged against a
# fixture database.
[ -r "$FORGEJO_DB" ] || {
    echo "Forgejo database is not readable: ${FORGEJO_DB}" >&2
    exit 69
}
SQLITE3=${SQLITE3:-sqlite3}
command -v "$SQLITE3" >/dev/null || {
    echo 'sqlite3 is required' >&2
    exit 69
}

# Open the database read-only through a file: URI.
#
# Two deliberate choices. `-readonly` alone still lets SQLite recover or
# checkpoint the WAL, which writes to a live service's database; the URI form
# with mode=ro keeps this strictly a reader. And `immutable=1` is NOT used even
# though it avoids touching the WAL entirely, because Forgejo is running: with
# immutable=1 SQLite ignores -wal, and every run recorded since the last
# checkpoint would silently vanish from the dashboard. A status page that
# quietly omits the newest run is worse than one that fails loudly.
db()
{
    "$SQLITE3" -readonly -noheader -separator '|' \
        "file:${FORGEJO_DB}?mode=ro" "$1"
}

install -d -m 0755 "$(dirname "$OUT_DIR")"
tmp_root=$(mktemp -d "${OUT_DIR%/*}/.ci-dashboard.XXXXXX")
trap 'rm -rf "$tmp_root"' EXIT HUP INT TERM

install -d -m 0755 "$tmp_root" "${tmp_root}/logs"

generated=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# --- helpers ---------------------------------------------------------------

# Forgejo stores status as an integer. These are the values observed on this
# instance across 12 runs and cross-checked against what the REST API reports
# for the same rows (1 -> success, 2 -> failure, 4 -> skipped).
status_name()
{
    case "$1" in
        0) echo unknown ;;
        1) echo success ;;
        2) echo failure ;;
        3) echo cancelled ;;
        4) echo skipped ;;
        5) echo waiting ;;
        6) echo running ;;
        7) echo blocked ;;
        *) echo "status-$1" ;;
    esac
}

# Escape for HTML text and attributes. Commit titles are author-controlled and
# land in both contexts, so quotes are escaped too -- without that, a title
# containing a double quote would break out of an attribute.
html_escape()
{
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"
}

# Escape for a JSON string. Backslash first, or it would double-escape the
# escapes added afterwards. Control characters are stripped rather than encoded:
# they have no place in a commit title and \u escaping them here would need more
# machinery than the payload justifies.
json_escape()
{
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g' -e 's/[[:cntrl:]]//g'
}

epoch_to_iso()
{
    [ -n "$1" ] && [ "$1" -gt 0 ] 2>/dev/null || { echo ''; return 0; }
    date -u -r "$1" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo ''
}

duration_text()
{
    _started=${1:-0}
    _stopped=${2:-0}
    { [ "$_started" -gt 0 ] && [ "$_stopped" -ge "$_started" ]; } 2>/dev/null || {
        echo ''
        return 0
    }
    _d=$((_stopped - _started))
    if [ "$_d" -lt 60 ]; then
        echo "${_d}s"
    else
        echo "$((_d / 60))m $((_d % 60))s"
    fi
}

# --- repository id ---------------------------------------------------------

repo_owner=${REPO_SLUG%%/*}
repo_name=${REPO_SLUG##*/}
repo_id=$(db "select r.id from repository r
    join \`user\` u on u.id = r.owner_id
    where u.lower_name = '$(printf '%s' "$repo_owner" | tr 'A-Z' 'a-z')'
      and r.lower_name = '$(printf '%s' "$repo_name" | tr 'A-Z' 'a-z')'
    limit 1;")
[ -n "$repo_id" ] || {
    echo "Repository not found in Forgejo: ${REPO_SLUG}" >&2
    exit 69
}

# --- runs and jobs ---------------------------------------------------------

runs=$(db "select \`index\`, id, status, event, ref, commit_sha,
                  coalesce(started, 0), coalesce(stopped, 0),
                  replace(replace(coalesce(title, ''), '|', ' '), char(10), ' ')
           from action_run
           where repo_id = ${repo_id}
           order by \`index\` desc
           limit ${RUN_LIMIT};")

runs_html="${tmp_root}/.runs.html"
runs_json="${tmp_root}/.runs.json"
: > "$runs_html"
: > "$runs_json"

total_runs=0
ok_runs=0
failed_runs=0
newest_status=''
newest_index=''
newest_finished=''
first_json=1

# A pipe would put this loop in a subshell and discard every counter it
# increments, so the query result goes through a file instead.
printf '%s\n' "$runs" > "${tmp_root}/.runs.raw"
while IFS='|' read -r run_index run_id run_status run_event run_ref \
    run_sha run_started run_stopped run_title; do
    [ -n "$run_index" ] || continue
    total_runs=$((total_runs + 1))

    run_status_name=$(status_name "$run_status")
    case "$run_status_name" in
        success) ok_runs=$((ok_runs + 1)) ;;
        failure|cancelled) failed_runs=$((failed_runs + 1)) ;;
    esac

    run_started_iso=$(epoch_to_iso "$run_started")
    run_stopped_iso=$(epoch_to_iso "$run_stopped")
    run_duration=$(duration_text "$run_started" "$run_stopped")
    short_sha=$(printf '%.12s' "$run_sha")
    branch=${run_ref##refs/heads/}

    if [ -z "$newest_index" ]; then
        newest_index=$run_index
        newest_status=$run_status_name
        newest_finished=$run_stopped_iso
    fi

    branch_html=$(printf '%s' "$branch" | html_escape)
    branch_json=$(printf '%s' "$branch" | json_escape)
    event_html=$(printf '%s' "$run_event" | html_escape)
    event_json=$(printf '%s' "$run_event" | json_escape)
    sha_html=$(printf '%s' "$run_sha" | html_escape)
    short_sha_html=$(printf '%s' "$short_sha" | html_escape)
    sha_json=$(printf '%s' "$run_sha" | json_escape)
    title_html=$(printf '%s' "$run_title" | html_escape)
    title_json=$(printf '%s' "$run_title" | json_escape)

    # Publish logs only for the newest LOG_RUNS runs.
    publish_logs=0
    [ "$total_runs" -le "$LOG_RUNS" ] && publish_logs=1

    jobs=$(db "select id, name, status, coalesce(started, 0),
                      coalesce(stopped, 0), coalesce(task_id, 0)
               from action_run_job
               where run_id = ${run_id}
               order by id;")

    jobs_html=''
    jobs_json=''
    printf '%s\n' "$jobs" > "${tmp_root}/.jobs.raw"
    while IFS='|' read -r job_id job_name job_status job_started \
        job_stopped job_task; do
        [ -n "$job_id" ] || continue
        job_status_name=$(status_name "$job_status")
        job_duration=$(duration_text "$job_started" "$job_stopped")
        job_name_html=$(printf '%s' "$job_name" | html_escape)
        job_name_json=$(printf '%s' "$job_name" | json_escape)

        log_rel=''
        if [ "$publish_logs" -eq 1 ] && [ "$job_task" -gt 0 ] 2>/dev/null; then
            log_src=$(db "select coalesce(log_filename, '')
                          from action_task where id = ${job_task};")
            if [ -n "$log_src" ]; then
                # log_filename is Forgejo-generated (owner/repo/<n>/<id>.log.zst)
                # but it still crosses into a filesystem path here, so reject
                # traversal rather than trusting the producer.
                case "$log_src" in
                    /*|*..*) log_src='' ;;
                esac
            fi
            if [ -n "$log_src" ] && [ -f "${ACTIONS_LOG_ROOT}/${log_src}" ]; then
                log_out="${tmp_root}/logs/${job_task}.txt"
                case "$log_src" in
                    *.zst)
                        zstdcat "${ACTIONS_LOG_ROOT}/${log_src}" 2>/dev/null |
                            head -c "$LOG_MAX_BYTES" > "$log_out" || true
                        ;;
                    *)
                        head -c "$LOG_MAX_BYTES" \
                            "${ACTIONS_LOG_ROOT}/${log_src}" > "$log_out" || true
                        ;;
                esac
                if [ -s "$log_out" ]; then
                    chmod 0644 "$log_out"
                    log_rel="logs/${job_task}.txt"
                else
                    rm -f "$log_out"
                fi
            fi
        fi

        if [ -n "$log_rel" ]; then
            job_log_html="<a class=\"joblog\" href=\"${log_rel}\">log</a>"
            job_log_json="\"log\": \"${log_rel}\""
        else
            job_log_html='<span class="joblog muted">no log</span>'
            job_log_json='"log": null'
        fi

        jobs_html="${jobs_html}
          <li class=\"job\">
            <span class=\"badge ${job_status_name}\">${job_status_name}</span>
            <span class=\"jobname\">${job_name_html}</span>
            <span class=\"muted\">${job_duration}</span>
            ${job_log_html}
          </li>"

        [ -n "$jobs_json" ] && jobs_json="${jobs_json},"
        jobs_json="${jobs_json}
        {\"name\": \"${job_name_json}\", \"status\": \"${job_status_name}\", \"duration\": \"${job_duration}\", ${job_log_json}}"
    done < "${tmp_root}/.jobs.raw"

    # Match this run to what it published. The build ID embeds the commit, so a
    # release directory can be attributed to a run without parsing a job log.
    #
    # A failed run is deliberately NOT credited with an artifact even when a
    # .pkg is present on disk. gatebsd-ci-build writes the package before it
    # verifies the catalogue signature, so a run that failed after that write
    # leaves a real-looking but unverified package behind. Offering it here with
    # the same styling as a released one invites an operator to install an
    # artifact the pipeline explicitly rejected.
    artifact_html=''
    artifact_json='null'
    build_dir=''
    case "$run_status_name" in
        success)
            build_dir=$(find "${RELEASE_ROOT}/builds" -maxdepth 1 -type d \
                -name "*-${short_sha}" 2>/dev/null | sort | tail -n 1)
            [ -n "$build_dir" ] || build_dir=$(find "$ARTIFACT_ROOT" -maxdepth 1 \
                -type d -name "*-${short_sha}" 2>/dev/null | sort | tail -n 1)
            ;;
    esac
    if [ -n "$build_dir" ]; then
        build_id=${build_dir##*/}
        pkg_file=$(find "$build_dir" -maxdepth 1 -type f -name 'gatebsd-*.pkg' \
            2>/dev/null | sort | head -n 1)
        pkg_name=${pkg_file##*/}
        case "$build_dir" in
            "${RELEASE_ROOT}"/*) art_url="${BASE_URL}/${PROJECT_SLUG}/releases/builds/${build_id}/" ;;
            *) art_url="${BASE_URL}/ci/artifacts/${build_id}/" ;;
        esac
        build_id_json=$(printf '%s' "$build_id" | json_escape)
        pkg_name_html=$(printf '%s' "$pkg_name" | html_escape)
        pkg_name_json=$(printf '%s' "$pkg_name" | json_escape)
        art_url_html=$(printf '%s' "$art_url" | html_escape)
        art_url_json=$(printf '%s' "$art_url" | json_escape)
        if [ -n "$pkg_name" ]; then
            artifact_html="<a class=\"pkg\" href=\"${art_url_html}${pkg_name_html}\">${pkg_name_html}</a>
            <a class=\"muted\" href=\"${art_url_html}\">directory</a>"
            artifact_json="{\"build_id\": \"${build_id_json}\", \"package\": \"${pkg_name_json}\", \"url\": \"${art_url_json}\"}"
        else
            artifact_html="<a class=\"muted\" href=\"${art_url_html}\">build directory</a>"
            artifact_json="{\"build_id\": \"${build_id_json}\", \"package\": null, \"url\": \"${art_url_json}\"}"
        fi
    elif [ "$run_status_name" = failure ]; then
        artifact_html='<span class="muted">build failed — no package published</span>'
    else
        artifact_html='<span class="muted">package not published</span>'
    fi

    cat >> "$runs_html" <<HTML
      <article class="run ${run_status_name}">
        <header>
          <span class="badge ${run_status_name}">${run_status_name}</span>
          <a class="runid" href="${FORGE_URL}/${REPO_SLUG}/actions/runs/${run_index}">#${run_index}</a>
          <span class="runtitle">${title_html}</span>
        </header>
        <div class="meta">
          <span>${event_html}</span>
          <span class="branch">${branch_html}</span>
          <a class="sha" href="${FORGE_URL}/${REPO_SLUG}/commit/${sha_html}">${short_sha_html}</a>
          <span>${run_started_iso}</span>
          <span>${run_duration}</span>
        </div>
        <ul class="jobs">${jobs_html}
        </ul>
        <div class="artifact">${artifact_html}</div>
      </article>
HTML

    [ "$first_json" -eq 1 ] || printf ',' >> "$runs_json"
    first_json=0
    cat >> "$runs_json" <<JSON

    {"index": ${run_index}, "status": "${run_status_name}", "event": "${event_json}",
     "branch": "${branch_json}", "commit": "${sha_json}", "title": "${title_json}",
     "started": "${run_started_iso}", "stopped": "${run_stopped_iso}",
     "duration": "${run_duration}", "artifact": ${artifact_json},
     "jobs": [${jobs_json}]}
JSON
done < "${tmp_root}/.runs.raw"

# --- releases --------------------------------------------------------------

releases_html="${tmp_root}/.releases.html"
releases_json="${tmp_root}/.releases.json"
: > "$releases_html"
: > "$releases_json"

current_version=''
current_target=$(readlink "${RELEASE_ROOT}/current" 2>/dev/null || true)
current_build=${current_target##*/}

first_json=1
# -type l, not a glob: a version entry is a symlink into builds/, so this keeps
# a stray regular file out of the release list. Newest version first -- `-V`,
# because a plain sort compares the version character by character and puts the
# whole 2.9.4..2.9.9 block above 2.9.15. Every release past the ninth in a minor
# series lands in the wrong place, and the newest one stops being on top, which
# is the only thing this table is read for.
find "${RELEASE_ROOT}/versions" -maxdepth 1 -type l 2>/dev/null | sort -V -r \
    > "${tmp_root}/.versions.raw" || : > "${tmp_root}/.versions.raw"

while IFS= read -r version_link; do
    [ -n "$version_link" ] || continue
    version=${version_link##*/}
    version_html=$(printf '%s' "$version" | html_escape)
    version_json=$(printf '%s' "$version" | json_escape)
    # A dangling version link means an advertised URL resolves to nothing, which
    # is how a repository breaks mid-upgrade. Surface it instead of hiding it.
    if [ ! -d "$version_link" ]; then
        cat >> "$releases_html" <<HTML
      <tr class="broken">
        <td>${version_html}</td><td colspan="3">dangling link — build removed</td>
      </tr>
HTML
        continue
    fi
    target=$(readlink "$version_link" 2>/dev/null || true)
    build_id=${target##*/}
    pkg_file=$(find "$version_link/" -maxdepth 1 -type f -name 'gatebsd-*.pkg' \
        2>/dev/null | sort | head -n 1)
    pkg_name=${pkg_file##*/}
    pkg_size=''
    [ -n "$pkg_file" ] && pkg_size=$(du -h "$pkg_file" 2>/dev/null | cut -f1)
    published=$(date -u -r "$(stat -f '%m' "$version_link/" 2>/dev/null || echo 0)" \
        '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo '')
    is_current=''
    [ "$build_id" = "$current_build" ] && {
        is_current=' current'
        current_version=$version
    }
    signed=no
    [ -f "${version_link}/packagesite.pkg" ] &&
        tar tf "${version_link}/packagesite.pkg" 2>/dev/null |
        grep -qx signature && signed=yes

    rel_url="${BASE_URL}/${PROJECT_SLUG}/releases/versions/${version}/"
    rel_url_html=$(printf '%s' "$rel_url" | html_escape)
    rel_url_json=$(printf '%s' "$rel_url" | json_escape)
    build_id_json=$(printf '%s' "$build_id" | json_escape)
    pkg_name_json=$(printf '%s' "$pkg_name" | json_escape)
    pkg_size_html=$(printf '%s' "$pkg_size" | html_escape)
    pkg_size_json=$(printf '%s' "$pkg_size" | json_escape)
    cat >> "$releases_html" <<HTML
      <tr class="release${is_current}">
        <td>
          <a href="${rel_url_html}">${version_html}</a>
          $([ -n "$is_current" ] && echo '<span class="badge success">current</span>')
        </td>
        <td>${published}</td>
        <td>${pkg_size_html}</td>
        <td>signature: ${signed}</td>
      </tr>
HTML

    [ "$first_json" -eq 1 ] || printf ',' >> "$releases_json"
    first_json=0
    printf '\n    {"version": "%s", "build_id": "%s", "package": "%s", "size": "%s", "published": "%s", "signed": %s, "current": %s, "url": "%s"}' \
        "$version_json" "$build_id_json" "$pkg_name_json" "$pkg_size_json" "$published" \
        "$([ "$signed" = yes ] && echo true || echo false)" \
        "$([ -n "$is_current" ] && echo true || echo false)" \
        "$rel_url_json" >> "$releases_json"
done < "${tmp_root}/.versions.raw"

# --- infrastructure health -------------------------------------------------

runner_row=$(db "select coalesce(name, ''), coalesce(version, ''),
                        coalesce(last_online, 0)
                 from action_runner
                 order by last_online desc limit 1;")
runner_name=$(printf '%s' "$runner_row" | cut -d'|' -f1)
runner_version=$(printf '%s' "$runner_row" | cut -d'|' -f2)
runner_seen=$(printf '%s' "$runner_row" | cut -d'|' -f3)
runner_seen_iso=$(epoch_to_iso "$runner_seen")
now=$(date -u '+%s')
# The runner polls continuously, so a stale last_online is the signal that the
# CI VM is down -- the failure mode where a push produces no run at all and
# nothing anywhere reports a problem.
runner_state=offline
if [ -n "$runner_seen" ] && [ "$runner_seen" -gt 0 ] 2>/dev/null; then
    [ "$((now - runner_seen))" -lt 300 ] && runner_state=online
fi
[ -n "$runner_name" ] || { runner_name='not registered'; runner_state=missing; }

mirror_ready=unknown
[ -f "${STATUS_DIR}/health-ready-ok" ] && mirror_ready=ready
disk_free=$(df -h /tank 2>/dev/null | awk 'NR == 2 {print $4}')

# --- render ----------------------------------------------------------------

template="${TEMPLATE_DIR}/ci-dashboard.html"
[ -f "$template" ] || {
    echo "Dashboard template is missing: ${template}" >&2
    exit 69
}

pipeline_state=unknown
[ -n "$newest_status" ] && pipeline_state=$newest_status

# awk rather than sed: the substituted values contain slashes and ampersands,
# both of which are special on a sed replacement side.
awk -v generated="$generated" \
    -v runs_file="$runs_html" \
    -v releases_file="$releases_html" \
    -v pipeline_state="$pipeline_state" \
    -v newest_index="${newest_index:-—}" \
    -v newest_finished="${newest_finished:-—}" \
    -v total_runs="$total_runs" \
    -v ok_runs="$ok_runs" \
    -v failed_runs="$failed_runs" \
    -v current_version="${current_version:-—}" \
    -v runner_name="$runner_name" \
    -v runner_version="$runner_version" \
    -v runner_state="$runner_state" \
    -v runner_seen="${runner_seen_iso:-—}" \
    -v mirror_ready="$mirror_ready" \
    -v disk_free="${disk_free:-—}" \
    -v forge_url="$FORGE_URL" \
    -v repo_slug="$REPO_SLUG" \
    -v base_url="$BASE_URL" \
    -v project_slug="$PROJECT_SLUG" '
    function emit(path) {
        while ((getline line < path) > 0) print line
        close(path)
    }
    /@@RUNS@@/     { emit(runs_file); next }
    /@@RELEASES@@/ { emit(releases_file); next }
    {
        gsub(/@@GENERATED@@/, generated)
        gsub(/@@PIPELINE_STATE@@/, pipeline_state)
        gsub(/@@NEWEST_INDEX@@/, newest_index)
        gsub(/@@NEWEST_FINISHED@@/, newest_finished)
        gsub(/@@TOTAL_RUNS@@/, total_runs)
        gsub(/@@OK_RUNS@@/, ok_runs)
        gsub(/@@FAILED_RUNS@@/, failed_runs)
        gsub(/@@CURRENT_VERSION@@/, current_version)
        gsub(/@@RUNNER_NAME@@/, runner_name)
        gsub(/@@RUNNER_VERSION@@/, runner_version)
        gsub(/@@RUNNER_STATE@@/, runner_state)
        gsub(/@@RUNNER_SEEN@@/, runner_seen)
        gsub(/@@MIRROR_READY@@/, mirror_ready)
        gsub(/@@DISK_FREE@@/, disk_free)
        gsub(/@@FORGE_URL@@/, forge_url)
        gsub(/@@REPO_SLUG@@/, repo_slug)
        gsub(/@@BASE_URL@@/, base_url)
        gsub(/@@PROJECT_SLUG@@/, project_slug)
        print
    }
' "$template" > "${tmp_root}/index.html"
chmod 0644 "${tmp_root}/index.html"

{
    printf '{\n'
    printf '  "generated": "%s",\n' "$generated"
    printf '  "pipeline": {"state": "%s", "latest_run": "%s", "finished": "%s",\n' \
        "$pipeline_state" "${newest_index:-}" "${newest_finished:-}"
    printf '               "runs": %s, "succeeded": %s, "failed": %s},\n' \
        "$total_runs" "$ok_runs" "$failed_runs"
    printf '  "runner": {"name": "%s", "version": "%s", "state": "%s", "last_seen": "%s"},\n' \
        "$(printf '%s' "$runner_name" | json_escape)" "$runner_version" \
        "$runner_state" "${runner_seen_iso:-}"
    printf '  "mirror": {"ready": "%s", "tank_free": "%s"},\n' \
        "$mirror_ready" "${disk_free:-}"
    printf '  "current_release": "%s",\n' "${current_version:-}"
    printf '  "releases": ['
    cat "$releases_json"
    printf '\n  ],\n'
    printf '  "runs": ['
    cat "$runs_json"
    printf '\n  ]\n'
    printf '}\n'
} > "${tmp_root}/status.json"
chmod 0644 "${tmp_root}/status.json"

rm -f "${tmp_root}"/.runs.html "${tmp_root}"/.runs.json \
    "${tmp_root}"/.releases.html "${tmp_root}"/.releases.json \
    "${tmp_root}"/.runs.raw "${tmp_root}"/.jobs.raw "${tmp_root}"/.versions.raw

# Swap the whole tree in one rename so a fetch never sees a half-written
# dashboard: the new tree is complete before it becomes reachable, and the old
# one stays intact until it does.
install -d -m 0755 "$(dirname "$OUT_DIR")"
staged="${OUT_DIR}.new.$$"
previous="${OUT_DIR}.old.$$"
rm -rf "$staged" "$previous"
cp -R "$tmp_root" "$staged"
chmod 0755 "$staged" "${staged}/logs"
if [ -d "$OUT_DIR" ]; then
    mv "$OUT_DIR" "$previous"
fi
mv "$staged" "$OUT_DIR"
rm -rf "$previous"

echo "CI dashboard published: ${BASE_URL}/ci/ (runs=${total_runs} latest=${pipeline_state})"
