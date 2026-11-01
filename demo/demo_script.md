# Kịch bản demo dự kiến — TV3 và TV4

**TODO, chưa có video hoặc lab đang vận hành.**

1. Giới thiệu hai máy, phiên bản thống nhất, IP private và 4 luật marker/SYN.
2. TV2 xác nhận lab được dành riêng cho lượt demo, capture hoạt động, log mới.
3. TV1 chạy runner sau khi hoàn thành: tối thiểu T01–T06 và T13–T14 ở live.
4. TV3 chỉ ra request/query/SYN trong PCAP, đối chiếu expected SID.
5. TV4 hiển thị alert, PASS/FAIL/INVALID, bảng chỉ số và liên kết bằng chứng.
6. Nếu live lỗi, trình bày PCAP offline đã kiểm chứng và video dự phòng;
   gắn nhãn rõ mode, không mô tả replay/video là chạy live vừa thực hiện.

TODO TV4: quay `demo.mp4` trước 13/12/2026, không lộ IP public/credential.
Video là đầu ra chia sẻ riêng, mặc định bị gitignore để tránh dữ liệu lớn.
