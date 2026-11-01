# Hạ tầng và tái lập — TV2 (TV1 kiểm tra bàn giao)

**Tài liệu chuẩn bị, chưa cài hay triển khai VPS.** Không dùng Docker.

## Hai VPS dùng chung

Cùng nhà cung cấp, region và VPC. Client sinh traffic; Server chạy nginx,
dnsmasq, Suricata và Python. Chỉ dùng IP private của Server làm đích thử.
Chưa có provider/IP/account thực tế. TV2 thay `.env.example` và config mẫu
trong bản local, giữ cấu hình máy thật ngoài Git hoặc dùng `*.local.*` bị ignore.
Các script chưa tự nạp `.env`; TV2 cần thống nhất cơ chế cấu hình.

Cloud firewall và firewall hệ điều hành cần cho phép từ Client private tới
Server private: TCP/80, UDP/53 (TCP/53 nếu nhóm thử DNS/TCP), TCP/8000–8019.
Nếu cloud firewall chặn trước Server, Suricata sẽ không thấy gói. Không mở
các cổng thử cho toàn Internet. SSH chỉ từ nguồn quản trị đã chọn.
Chưa cần dịch vụ nghe ở 8000–8019: SYN vào cổng đóng vẫn phải tới Server.

Mỗi người có tài khoản SSH/thư mục Git riêng. TV2 thiết lập quyền tối thiểu
cho capture/Suricata/Nmap và kết nối SSH Server→Client nếu runner dùng SSH.
Không chia sẻ private key hoặc thêm password vào script. Lượt live chính thức
phải đặt lịch và có lock để không người khác tạo traffic gây nhiễu.

## Phương án hai VM local

Ubuntu Server 24.04 LTS cùng phiên bản, VirtualBox nếu phù hợp phần cứng.
NAT để cài gói; Internal Network `ids-lab` để thử, ví dụ Client 10.10.10.10/24,
Server 10.10.10.20/24. Không giả định tên interface là eth0, xác định bằng
`ip -br address` và `ip route`. Không giả định OVA chuyển được giữa x86 và ARM.
TV2 dựng chuẩn và ghi cách tái lập; TV1 kiểm tra bàn giao.

## Công cụ và phiên bản

Client: curl, dnsutils (dig), Nmap, tcpdump, SSH, Git.
Server: Suricata, nginx, dnsmasq, Python 3 >=3.10, venv/pip, tcpdump, SSH, Git.
Wireshark dùng đối chiếu PCAP trên máy phân tích; Python runtime ưu tiên stdlib.
TV2 chốt đúng một phiên bản Suricata trước thu số liệu và lưu lệnh `suricata -V`,
`suricata --build-info` trong hồ sơ. Tài liệu 8.0.0 chỉ là tham khảo.
Không có script cài đặt tự động hoạt động ở thời điểm bộ khung.

## Cấu hình mẫu và kiểm tra dự kiến

- `config/suricata.yaml`: overlay, nạp sau file đầy đủ của bản Suricata đã cài.
  Không thay file hệ thống bằng overlay này. HOME_NET có thể gồm cả hai máy;
  rules dùng LAB_CLIENT/LAB_SERVER để Client không bị loại bởi EXTERNAL_NET.
- `config/nginx.conf`: một server block để đưa vào http{} / sites-enabled theo
  bản đóng gói. Chạy `nginx -t` sau tích hợp, tránh server block mặc định xung đột.
- `config/dnsmasq.conf`: cấu hình resolver lab; kiểm tra xung đột cổng 53 với
  systemd-resolved, bind đúng IP private, `dnsmasq --test --conf-file=...`.
- TV2 phải kiểm tra parser HTTP/DNS trong file đầy đủ, checksum/offload và packet
  drop. Không tắt checksum kiểm tra hàng loạt trước khi xác minh bằng PCAP.

Lệnh minh họa từ repo root, **chỉ dùng sau khi TV2 hoàn tất môi trường**;
chưa được thực thi/kiểm chứng trong bộ khung. Đường dẫn, quyền, interface phải thay:

```bash
# Kiểm tra cấu hình/luật với đúng Suricata mà nhóm chốt
suricata -T -c /etc/suricata/suricata.yaml --include config/suricata.yaml -S rules/local.rules
# Offline: thư mục đích mới, engine mới cho MỖI ca; runner còn TODO
suricata -c /etc/suricata/suricata.yaml --include config/suricata.yaml -S rules/local.rules -r tests/pcaps/T01.pcap -l /path/to/new-case-dir
# Live: thay interface; cần quyền capture phù hợp; runner còn TODO
suricata -c /etc/suricata/suricata.yaml --include config/suricata.yaml -S rules/local.rules -i PRIVATE_INTERFACE -l /path/to/new-live-case-dir
```

`-S` chỉ nạp luật nhóm để hạn chế SID từ ruleset khác; lưu log kiểm tra -T.
`-l` cần thư mục tồn tại, riêng cho ca và có quyền ghi. Với offline, đợi tiến trình
thoát, kiểm tra mã thoát/log trước đánh giá. Không dùng `-r tests/pcaps/` cho 14 ca
vì trạng thái có thể được giữ giữa file. Với live, kết thúc sạch, đợi engine và
capture đóng file; không đọc EVE khi còn ghi. Không chạy hai engine cạnh tranh
trên cùng ca; TV2 quản lý service Suricata hệ thống và tiến trình do runner chạy.

## Traffic dự kiến — TV3 còn phải triển khai

HTTP dùng curl HTTP bản rõ, URI/User-Agent theo CSV; T12 đúng 3 request.
DNS dùng dig gửi trực tiếp tới Server private, `+tries=1`, truy vấn A.
SYN dùng Nmap SYN scan với quyền raw packet; dự kiến `-sS -Pn -n --max-retries 0`,
T13 dải `-p 8000-8019` với tốc độ được kiểm chứng để đạt cửa sổ 10 giây;
T14 chỉ `-p 8000` và xác nhận PCAP đúng một SYN. Không dùng TCP connect scan
thay SYN scan khi thiếu quyền. Mã thoát Nmap thành công không đủ xác nhận traffic.

Không chạy các lệnh này tới IP ngoài lab. Chưa có traffic được sinh bởi scaffold.
TV3 tạo PCAP sạch tại Server; TV4 dùng mock để làm parser độc lập.
