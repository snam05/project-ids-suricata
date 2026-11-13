# Các hàm dùng chung cho hai lệnh chạy từ checkout của dự án.

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
results_dir="$repo_dir/results"

die() {
  printf 'Lỗi: %s\n' "$*" >&2
  exit 1
}

update_checkout() {
  local branch status
  command -v suricata >/dev/null || die 'Cần cài Suricata trên Server.'
  branch=$(git branch --show-current)
  [[ $branch == main ]] || die 'Chạy từ nhánh main của bản clone trên Server.'
  status=$(git status --porcelain --untracked-files=no)
  [[ -z $status ]] || \
    die 'Bản clone có thay đổi đã theo dõi. Dùng bản clone triển khai sạch để cập nhật từ GitHub.'
  git pull --quiet --ff-only origin main
  [[ $(git rev-parse HEAD) == "$(git rev-parse FETCH_HEAD)" ]] || \
    die 'HEAD khác origin/main. Kiểm tra commit cục bộ trước khi triển khai.'
}

set_suricata_args() {
  local run_dir=$1
  suricata_args=(
    --init-errors-fatal
    -c "$run_dir/config/suricata.yaml"
    --set "default-rule-path=$run_dir/rules"
  )
}

check_config() (
  local run_dir=$1 check_dir
  check_dir=$(mktemp -d -- "$run_dir/.config-check.XXXXXX")
  trap 'rm -rf -- "$check_dir"' EXIT
  cd -- "$run_dir"
  test -s "$run_dir/rules/local.rules" || die 'rules/local.rules thiếu hoặc rỗng.'
  set_suricata_args "$run_dir"
  suricata -T -v "${suricata_args[@]}" -l "$check_dir"
)

prepare_run() (
  # Giữ errexit vì caller lấy đường dẫn lượt bằng command substitution.
  set -e
  local mode=$1 run_dir commit pcap case_number run_time
  local index=0
  shift
  mkdir -p -- "$results_dir"
  cd -- "$repo_dir"
  exec 9>"$results_dir/.suricata.lock"
  if ! flock -n 9; then
    printf 'Đang chờ lượt khác chuẩn bị dữ liệu từ repo.\n' >&2
    flock 9
  fi

  update_checkout >&2
  commit=$(git rev-parse HEAD)
  git log -1 --no-patch --no-notes --no-show-signature --color=never \
    --format="[commit][$mode] origin/main | %H | %cI | %an | %s" "$commit" >&2
  suricata -V >&2
  run_time=$(TZ=Asia/Ho_Chi_Minh date '+%Y%m%dT%H%M%S%z')
  run_dir=$(mktemp -d -- "$results_dir/${mode}_${run_time}.XXXXXX")
  trap 'rm -rf -- "$run_dir"' EXIT
  git archive "$commit" config/suricata.yaml rules | tar -xf - -C "$run_dir"
  printf '%s\n' "$commit" > "$run_dir/git-commit.txt"

  for pcap in "$@"; do
    [[ -f $pcap && -r $pcap ]] || die "Không đọc được PCAP: $pcap"
    index=$((index + 1))
    printf -v case_number '%03d' "$index"
    mkdir -- "$run_dir/$case_number"
    cp --reflink=auto -- "$pcap" "$run_dir/$case_number/input.pcap"
  done

  exec 9>&-
  check_config "$run_dir" >&2
  trap - EXIT
  printf '%s\n' "$run_dir"
)
