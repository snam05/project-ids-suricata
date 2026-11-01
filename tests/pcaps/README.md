# Bộ PCAP đầu vào chuẩn — TV3

TODO: tạo T01.pcap … T14.pcap bằng traffic lab thật, tại phía Server/cảm biến.
Chưa có PCAP thực tế. Không tạo tệp rỗng mang đuôi `.pcap`.

Mỗi PCAP phải có ghi chú: Client/Server, interface, lệnh và filter capture,
thời điểm, phiên bản công cụ, SHA-256, số gói và điều kiện traffic đã kiểm tra.
HTTP cần đủ handshake/request; DNS phải có query; T12 đúng 3 request;
T13 kiểm tra 20 cổng, ít nhất 10 SYN khớp trong 10 giây; T14 một SYN không retry.
Cắt riêng từng ca, tránh traffic nền; ẩn hoặc loại bỏ dữ liệu thật trước khi commit.

PCAP thư mục này được phép Git theo dõi, nên tự kiểm tra kích thước và dữ liệu nhạy cảm.
Bản dùng mỗi lượt được runner sao chép sang `results/<run>/<test_id>/input.pcap`.
42 lượt offline là 14 PCAP × 3 lượt độc lập, engine mới cho từng ca; không nối
cả thư mục PCAP vào một engine duy nhất vì trạng thái threshold có thể truyền qua ca.
