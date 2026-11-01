# Kế hoạch nhóm 4 người

| Thành viên | File chính | Đầu vào → đầu ra | Việc tiếp theo |
| --- | --- | --- | --- |
| TV1 — trưởng nhóm | src/run_tests.py, src/eval_metrics.py | CSV + ngữ cảnh run + parsed EVE → điều phối, results.csv, metrics.json | Lock/run_id, runner live/offline, xác minh bằng chứng, tích hợp và đánh giá |
| TV2 — hạ tầng | config/*, scripts/lab.sh | mô hình + phiên bản đã chốt → Client/Server, dịch vụ, capture, SSH | Dựng chuẩn, private network/firewall, quyền công cụ, kiểm tra -T, hướng dẫn tái lập |
| TV3 — luật/dữ liệu | rules/local.rules, tests/tests.csv, scripts/traffic_gen.sh, tests/pcaps/ | ca thử → traffic và PCAP chuẩn có ghi nguồn | Kiểm chứng luật thật, hoàn thiện generator, PCAP đủ 14 ca, kịch bản demo |
| TV4 — log/trình bày | src/eve_parser.py, src/make_report.py, tests/fixtures/, tests/test_eve_parser.py | EVE → alerts/lỗi; kết quả đã đánh giá → HTML | Tích hợp parser, kiểm tra phạm vi log, renderer, video dự phòng |

TV1 viết tổng quan ngắn, khảo sát, đánh giá, kết luận; biên tập báo cáo và ghép slide.
TV2 viết hạ tầng/tái lập. TV3 viết luật và kiểm thử. TV4 viết xử lý log/trình bày.
Mỗi người tự soạn phần báo cáo/slide của mình. TV1 không nhận thay việc dựng hạ tầng.

| Tuần | Thời gian | Kết quả cần đạt |
| --- | --- | --- |
| 10 | 02–08/11/2026 | TV2 dựng chuẩn; TV1 kiểm tra bàn giao; chốt phiên bản và hợp đồng |
| 11 | 09–15/11 | TV3 kiểm chứng 4 luật/T01–T14; TV4 parser/mock; TV1 runner tối thiểu |
| 12 | 16–22/11 | Tích hợp một luồng đầy đủ, kiểm chứng PCAP và điều kiện INVALID |
| 13 | 23–29/11 | Hoàn thiện live/offline; **chốt tính năng 29/11** |
| 14 | 30/11–06/12 | 42 lượt offline, live tối thiểu 8 ca; **đủ số liệu + báo cáo đầy đủ 06/12** |
| 15 | 07–13/12 | **Đóng băng code 10/12**, hoàn tất nội bộ 13/12, slide/video |
| 16 | 14–18/12 | Sửa lỗi, kiểm tra gói nộp, diễn tập; **hạn cuối 18/12/2026** |

Trước số liệu chính thức: expected đã chốt, phiên bản/hash đầy đủ, lab độc quyền,
PCAP đã kiểm tra. 14 ca × 3 lượt offline độc lập = 42 ca/lượt, engine mới mỗi ca.
Live tối thiểu T01–T06 + T13–T14. Tách bảng live/offline; mock không vào số liệu.

Làm việc qua Git: nhánh tv1/runner, tv2/lab, tv3/rules-data, tv4/log-report;
commit nhỏ, pull request để người khác đọc trước merge. Chốt hợp đồng chung trước
khi sửa CSV/schema. Giữ main chạy được kiểm tra bộ khung. Không commit .env thật,
key/token, địa chỉ VPS thật, PCAP có dữ liệu cá nhân hoặc ảnh VM/video lớn.
