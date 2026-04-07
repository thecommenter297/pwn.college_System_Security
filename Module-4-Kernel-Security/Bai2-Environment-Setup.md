# Kernel Security 2: Thiết lập môi trường (Environment Setup)

Lập trình và khai thác Kernel là một công việc đầy rủi ro. Không giống như userspace (khi code lỗi thì process bị `Segmentation fault`), nếu code kernel của bạn bị lỗi (ví dụ: truy cập sai vùng nhớ), **toàn bộ hệ điều hành sẽ bị crash (Kernel Panic) và máy tính sẽ khởi động lại**. 

Do đó, KHÔNG BAO GIỜ thực hành trên máy thật. Chúng ta bắt buộc phải sử dụng môi trường giả lập (Virtual Machine / Emulator).

## 1. Thành phần của một môi trường Kernel CTF tiêu chuẩn

Trong mọi giải CTF hoặc khi bạn tải một firmware/môi trường về để nghiên cứu, bạn thường sẽ nhận được 3 file cốt lõi sau:

1.  `bzImage`: File chứa Kernel đã được biên dịch và nén lại (chữ 'b' là big, chữ 'z' là zlib nén).
2.  `rootfs.cpio`: File hệ thống (File System) chứa các công cụ userspace (như `/bin/sh`, `/bin/cat`...) và file cấu hình khởi động.
3.  `run.sh`: Một bash script gọi QEMU để chạy `bzImage` cùng với `rootfs.cpio`.

**Cài đặt các gói phụ thuộc cần thiết (Copy-paste để cài đặt):**
```bash
sudo apt update
sudo apt install -y qemu-system-x86 qemu-utils gcc gdb cpio build-essential wget
```

## 2. Thao tác với File System (Unpack & Pack `rootfs.cpio`)
*(Bổ sung cực kỳ quan trọng cho CTF)*

Để đưa file mã nguồn exploit (`exploit.c`) hoặc file thực thi (`exploit`) của bạn vào máy ảo, bạn phải giải nén `rootfs.cpio`, chép file vào, và đóng gói lại. Đây là thao tác bạn sẽ phải làm đi làm lại hàng nghìn lần.

**A. Kịch bản giải nén (Unpack):**
```bash
# Tạo một thư mục để chứa file system
mkdir initramfs
cd initramfs

# Giải nén cpio (Lưu ý: phải dùng quyền gốc của cpio, nếu không symlink sẽ bị lỗi)
cpio -idm < ../rootfs.cpio
```
*Tip cho hacker:* Sau khi giải nén, hãy mở file `initramfs/etc/init.d/rcS` (hoặc `initramfs/init`). Bạn có thể sửa lệnh `setuidgid 1000` thành `setuidgid 0` để tạm thời có quyền root, giúp bạn khảo sát môi trường dễ dàng hơn trước khi thực sự viết exploit bypass.

**B. Kịch bản đóng gói (Pack):**
Sau khi bạn đã copy file `exploit` đã compile vào thư mục `initramfs`, hãy dùng lệnh sau để nén lại.
```bash
# Đứng BÊN TRONG thư mục initramfs
find . -print0 | cpio -o --null --format=newc > ../rootfs_modified.cpio
```
*(Bây giờ, hãy sửa file `run.sh` để QEMU boot bằng file `rootfs_modified.cpio` mới của bạn).*

## 3. Trích xuất `vmlinux` (Tìm ROP Gadget)
*(Bổ sung phục vụ săn 0-day và viết KROP)*

File `bzImage` là file nén, bạn **không thể** ném nó vào IDA Pro, GDB hay `ROPgadget` để phân tích được. Bạn cần một file định dạng ELF chưa nén chứa các symbol, gọi là `vmlinux`.

Mã nguồn Linux cung cấp sẵn một script thần thánh để giải nén bzImage.

**Lệnh thực thi ngay:**
```bash
# Tải script extract-vmlinux từ repo của Linus Torvalds
wget https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux
chmod +x extract-vmlinux

# Trích xuất vmlinux từ bzImage
./extract-vmlinux bzImage > vmlinux

# Kiểm tra xem đã ra file ELF 64-bit chưa
file vmlinux
```
*Sau bước này, bạn có thể chạy `ROPgadget --binary vmlinux > gadgets.txt` để tìm các lệnh ROP phục vụ cho việc leo quyền.*

## 4. Debugging Kernel với GDB từ bên ngoài

Giống như slide đã đề cập, để debug kernel, bạn phải attach GDB từ **bên ngoài** máy ảo. QEMU hỗ trợ sẵn điều này.

**Bước 1: Chỉnh sửa file `run.sh`**
Mở file `run.sh` của bạn lên. 
1.  Đảm bảo cờ `kaslr` trong tham số `-append` bị đổi thành `nokaslr` (Tắt Kernel ASLR để địa chỉ bộ nhớ cố định, dễ debug).
2.  Thêm tham số `-s` (Mở cổng debug 1234) và `-S` (Đóng băng CPU ngay lúc boot để chờ GDB attach) vào lệnh khởi chạy qemu.

Ví dụ lệnh khởi chạy qemu đã sửa:
```bash
qemu-system-x86_64 \
    -kernel bzImage \
    -initrd rootfs_modified.cpio \
    -append "console=ttyS0 quiet pti=on nokaslr" \
    -monitor /dev/null \
    -m 256M -nographic \
    -s -S   # <-- THÊM HAI THAM SỐ NÀY
```

**Bước 2: Viết script tự động Attach GDB**
Tạo một file tên là `debug.gdb` với nội dung sau:
```gdb
file vmlinux
target remote localhost:1234
# Đặt breakpoint tại hàm xử lý syscall open (ví dụ)
b do_sys_open 
c
```

**Bước 3: Thực hành Debug**
1.  Mở Terminal 1: Chạy lệnh `./run.sh` (Màn hình sẽ đen xì vì QEMU đang chờ GDB).
2.  Mở Terminal 2: Chạy lệnh:
```bash
gdb -x debug.gdb
```
> **Cảnh báo cực kỳ quan trọng từ tác giả (Slide 2):** Khi debug trong không gian Kernel, các ngắt (interrupts) phần cứng xảy ra liên tục. Nếu bạn dùng lệnh `ni` (next instruction), GDB có thể bị kẹt hoặc crash do nó cố gắng step qua một hàm xử lý ngắt dài vô tận. **Quy tắc vàng: Chỉ dùng `si` (step into) hoặc `finish` (chạy hết hàm hiện tại) khi debug Kernel.**

## 5. Tìm kiếm Kernel Symbols (`/proc/kallsyms`)

Khi bạn cần gọi một hàm của Kernel trong shellcode của mình (như `commit_creds`, `prepare_kernel_cred`), bạn cần biết hàm đó nằm ở địa chỉ bộ nhớ nào.

File `/proc/kallsyms` chứa danh sách toàn bộ địa chỉ của các hàm và biến trong Kernel.

**Cách tra cứu bên trong máy ảo QEMU:**
```bash
cat /proc/kallsyms | grep commit_creds
cat /proc/kallsyms | grep prepare_kernel_cred
```
*Lưu ý bảo mật:* Nếu hệ thống bật tính năng `kptr_restrict`, user thường sẽ chỉ thấy các địa chỉ toàn số 0 (`0000000000000000`). Bạn phải có quyền root (khi đang test) hoặc tìm ra một lỗi **Memory Leak** (rò rỉ bộ nhớ) để tính toán ra địa chỉ thực tế.

## 6. Lên đồ săn 0-day: Syzkaller (Bonus)
*(Khởi động vũ khí hạng nặng)*

Nếu bạn nhắm tới 0-day, gdb tay là chưa đủ. **Syzkaller** (phát triển bởi Google) là một Fuzzer chuyên dụng để tìm lỗi Kernel bằng cách tạo ra hàng triệu kịch bản gọi Syscall ngẫu nhiên. Nó là thủ phạm tìm ra hàng ngàn CVE Linux những năm gần đây.

**Cài đặt nhanh Syzkaller:**
Yêu cầu hệ thống phải có ngôn ngữ `Go`.
```bash
# Cài Go
wget https://go.dev/dl/go1.21.3.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Tải và build Syzkaller
git clone https://github.com/google/syzkaller.git
cd syzkaller
make
```
*(Bạn sẽ cấu hình Syzkaller liên kết với file `bzImage` và một `rootfs` có hỗ trợ ssh, sau đó chạy `bin/syz-manager -config my.cfg` để nó tự động "bắn" máy ảo QEMU tìm crash. Chi tiết phần này rất dài, sẽ được ứng dụng khi bạn thực sự bắt tay tìm 0-day trên nhánh kernel master).*
