# Hợp đồng dữ liệu — TV1/TV3/TV4

## Danh mục trước lần chạy

`tests/tests.csv` có đúng thứ tự cột:

```text
test_id,description,protocol,target_ip,target_port,input_spec,expected_sids
```

- `test_id`: T01–T14, duy nhất; `protocol`: HTTP, DNS hoặc TCP_SYN.
- `target_ip`: IPv4 private của Server. Hiện 10.10.10.20 là ví dụ local.
- `target_port`: 80, 53 hoặc cổng đầu dải SYN (8000).
- `input_spec`: JSON object nằm trong ô CSV (dùng csv/JSON parser, không `eval`
  và không ghép thành shell command). HTTP: `uri`, `user_agent`, `repeat`;
  DNS: `query`, `qtype`, `transport`, `tries`; SYN: `ports`, `syn_packets`,
  `retries`, và `max_window_seconds` cho T13.
- `expected_sids`: số nguyên phân cách `;`, rỗng = không mong alert.
  Chốt kỳ vọng và hash danh mục trước chạy chính thức.

Runner đọc danh mục ở Server, gọi Client qua SSH là phương án dự kiến.
TV1 và TV3 phải chốt cách truyền input_spec; chưa có CLI chạy traffic thực tế.
Không thực thi input_spec bằng shell. Không sửa expected sau khi thấy kết quả.

## Dữ liệu mỗi ca/lượt

Mỗi ca có `input.pcap`, `eve.json`, `manifest.json`. `run_id` duy nhất
bao gồm lượt, mode được ghi rõ; runner gắn test_id/run_id từ ngữ cảnh thư mục.
EVE không tự có hai trường này. Không trộn EVE nhiều ca khi live chưa có cơ chế
phân tách đáng tin cậy. Đề xuất tiến trình capture/Suricata riêng cho mỗi ca.

Manifest **dự kiến**, TV1/TV2 còn phải triển khai:

| Nhóm | Trường cần ghi |
| --- | --- |
| Nhận diện | schema_version, run_id, test_id, mode=live/offline, fixture=false |
| Phiên bản | Suricata, hệ điều hành, Python, công cụ traffic, Git commit |
| Cấu hình | hash SHA-256 cấu hình đầy đủ + overlay hiệu lực, rules, danh mục |
| Đầu vào | IP lab, interface, input_spec, PCAP path/hash/số gói |
| Thực thi | argv dạng mảng, cwd, thời điểm bắt đầu/kết thúc có timezone, exit codes |
| Hoàn tất | engine_stopped, capture_closed, log_complete, parser_error_count |
| Hợp lệ | traffic_valid, cách kiểm chứng, người kiểm tra, lý do INVALID |

Không đưa credential, SSH private key, nội dung `.env` hoặc thông tin VPS thật
vào manifest public. Log có thông tin thật nằm ở results/ bị ignore. Hash không
thay thế kiểm tra traffic. Giữ bằng chứng stdout/stderr và thống kê drop khi cần.

## Kết quả và tiêu chí

`results.csv`, mỗi ca/lượt một dòng:

```text
run_id,test_id,expected_sids,observed_sids,traffic_valid,status,evidence_dir
```

SID ghi dạng tập đã sắp xếp, phân cách `;`; bool CSV dùng `true`/`false`
phải được parse tường minh (không dùng `bool("false")`). Khi triển khai cần từ chối
trùng cặp run_id/test_id và schema sai. `traffic_valid` chỉ phản ánh traffic;
`status=INVALID` vẫn có thể đi cùng `traffic_valid=true` nếu engine/log lỗi.

- **PASS**: traffic/bằng chứng/engine/log hợp lệ và hai tập SID bằng nhau.
- **FAIL**: lần chạy hợp lệ nhưng tập SID khác nhau, kể cả SID ngoài nhóm.
- **INVALID**: thiếu PCAP/EVE/manifest; traffic sai/chưa tới cảm biến;
  engine/traffic/capture lỗi; log lỗi/cắt dở; chưa đóng engine hoặc thiếu bằng chứng.
- Không alert chưa đủ để ca âm PASS: PCAP phía Server phải có request/query/SYN.
- Parser trả số dòng và lỗi theo dòng; bất kỳ lỗi parse nào cũng chặn đánh giá thật.
  Lỗi I/O/encoding phải được runner bắt và chuyển INVALID, không thay bằng EVE rỗng.
- Timestamp parser hiện giữ chuỗi; TODO TV4/TV1 kiểm tra thời gian, timezone,
  IP/flow và phạm vi ca khi tích hợp. Log rỗng không tự chứng minh ca âm thành công.

`evaluate_case()` đã có logic thuần; cờ hợp lệ do caller cung cấp. Hàm này **chưa**
đọc/xác minh PCAP hoặc manifest. Đây là phần tích hợp còn TODO.

## Chỉ số

Tính trên từng cặp ca–SID, đúng 4 SID 1000001–1000004. Loại INVALID:

| Kỳ vọng có SID | Quan sát có SID | Đếm |
| --- | --- | --- |
| Có | Có | TP |
| Có | Không | FN |
| Không | Có | FP |
| Không | Không | TN |

Expected SID 1 nhưng observed SID 2 → FN cho SID 1 và FP cho SID 2, ca FAIL.
T11 có hai SID; T12 dù có 3 alert vẫn chỉ một ca và một SID kỳ vọng.
SID ngoài bộ nhóm vẫn làm ca FAIL; không thêm SID đó vào ma trận 4 SID.
Precision = TP/(TP+FP), Recall = TP/(TP+FN); mẫu số 0 → N/A
(`null` trong metrics.json). `aggregate_metrics()` đã có kiểm thử logic này;
caller còn phải bảo đảm dữ liệu cùng mode, không trùng lượt, không mock.
42 ca offline hợp lệ tạo 168 cặp ca–SID; số alert không phải số ca.
Thời gian xử lý cả PCAP không phải độ trễ từng gói; kết luận giới hạn trong lab.
