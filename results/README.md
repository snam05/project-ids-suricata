# Đầu ra runtime — chưa có kết quả thực nghiệm

Thư mục này bị gitignore trừ README. Runner sẽ tạo, không viết tay kết quả:

```text
offline_<run_id>/
  T01/{input.pcap,eve.json,manifest.json}
  ... T14/
  results.csv
  metrics.json
  report.html
live_<run_id>/
  ... (tách riêng)
```

`run_id` duy nhất cho mỗi lượt; test_id xác định thư mục ca. Không ghi đè một run cũ.
Có thể lưu thêm stdout/stderr, config snapshot và hash. Chỉ đánh giá sau khi engine
đã thoát thành công, capture đã đóng, kiểm chứng PCAP và EVE không lỗi.
Manifest/schema xem `docs/data-contract.md`. Bản nộp chia sẻ bằng chứng đã rà soát,
không đưa log/IP/mật khẩu VPS thật vào repository public.
