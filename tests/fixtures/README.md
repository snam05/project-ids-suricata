# Dữ liệu giả cho kiểm thử code (TV4)

Tất cả dữ liệu ở đây là **MOCK**, không phải log Suricata thật hoặc số liệu lab.
`mock_eve.json` dùng JSON Lines dù đuôi `.json`: hai alert trùng SID và một HTTP event.
`mock_results.csv` dùng cho phát triển renderer; đường dẫn bằng chứng cố ý không tồn tại.
Không đưa các dòng này vào metrics/báo cáo thực nghiệm. `traffic_valid=true` trong mock
chỉ minh họa schema, không phải xác nhận đã có traffic.
Thêm ca JSON hỏng/schema sai qua unit test bằng thư mục tạm.
