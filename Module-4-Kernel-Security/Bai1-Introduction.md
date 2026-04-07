# Kernel Security 1: Giới thiệu về Kernel

## 1. Kernel là gì? Trái tim của Hệ điều hành

Hãy tưởng tượng một hệ điều hành như một quốc gia. Các chương trình bạn chạy hàng ngày (trình duyệt, game, terminal...) giống như các "tiểu bang" riêng lẻ. Mỗi tiểu bang có luật lệ và không gian riêng. **Kernel** chính là "chính phủ liên bang" - cơ quan quyền lực trung ương.

> **Vai trò của Kernel:**
> *   **Quản lý tài nguyên:** Phân phối CPU, bộ nhớ (RAM), và các thiết bị phần cứng (ổ cứng, card mạng, USB) cho các "tiểu bang" (process).
> *   **Thiết lập luật lệ:** Đảm bảo các process không xung đột, không xâm phạm bộ nhớ của nhau.
> *   **Giao tiếp:** Là cầu nối duy nhất giữa phần mềm (các process) và phần cứng.

Đối với một hacker, chiếm được quyền điều khiển Kernel (chạy mã ở **Ring 0**) đồng nghĩa với việc chiếm được toàn bộ hệ thống. Bạn không còn là một công dân bình thường mà đã trở thành "nhà cầm quyền", có thể làm mọi thứ.

## 2. Tài nguyên độc quyền: Những "Chìa khóa Vàng" của Kernel

Kernel có những quyền năng mà các chương trình thông thường không bao giờ được phép chạm tới. Việc truy cập trái phép những tài nguyên này sẽ khiến CPU ngay lập tức tạo ra một lỗi (exception) và hệ điều hành sẽ tiêu diệt process vi phạm.

Các tài nguyên này được bảo vệ ở cấp độ phần cứng (CPU). Dưới đây là một vài ví dụ trên kiến trúc x86-64:

*   **Lệnh đặc biệt:**
    *   `hlt`: Dừng hoạt động của CPU. Nếu một process bình thường có thể chạy lệnh này, nó sẽ làm treo toàn bộ máy.
    *   `in`, `out`: Đọc/ghi trực tiếp vào các cổng (port) của phần cứng. Đây là cách driver giao tiếp với thiết bị.

*   **Thanh ghi điều khiển (Control Registers):**
    *   `cr3`: Đây là thanh ghi cực kỳ quan trọng, nó chứa **địa chỉ vật lý** của Page Table cao nhất (PML4). Nói cách khác, `cr3` quyết định "tấm bản đồ" mà CPU dùng để dịch địa chỉ ảo (virtual address) của một process sang địa chỉ vật lý (physical address) trên RAM.
    > **Góc nhìn Hacker:** Kẻ tấn công có thể làm gì nếu ghi đè được `cr3`? Họ có thể trỏ nó tới một Page Table giả mạo, từ đó bypass mọi cơ chế bảo vệ bộ nhớ, đọc/ghi toàn bộ RAM của hệ thống một cách vô hình.

*   **Thanh ghi đặc thù model (Model-Specific Registers - MSR):**
    *   `MSR_LSTAR` (Long Syscall Target Address Register): Thanh ghi này lưu địa chỉ của hàm xử lý `syscall` trong kernel. Khi một chương trình ở userspace gọi lệnh `syscall`, CPU sẽ nhìn vào `MSR_LSTAR` để biết phải nhảy tới đâu trong kernel.
    > **Góc nhìn Hacker:** Nếu có thể ghi đè `MSR_LSTAR`, kẻ tấn công có thể hook (móc nối) toàn bộ syscall, trỏ chúng về shellcode của mình. Đây là một kỹ thuật rootkit cực kỳ mạnh mẽ để theo dõi hoặc chiếm quyền điều khiển hệ thống.

## 3. Privilege Levels (Rings): Phân cấp Quyền lực

Để quản lý việc truy cập các tài nguyên nhạy cảm, CPU x86-64 sử dụng một hệ thống phân cấp quyền lực gọi là "Rings" (Vòng bảo vệ).

*   **Ring 3 (Userspace):** Vòng ngoài cùng, quyền lực thấp nhất. Đây là nơi các chương trình bình thường như trình duyệt, game, terminal của bạn hoạt động. Chúng bị giới hạn và phải "xin phép" Kernel mỗi khi muốn làm gì đó đặc biệt (như đọc file, gửi gói tin mạng).
*   **Ring 1 & 2:** Hầu như không được sử dụng trong các hệ điều hành hiện đại như Linux hay Windows.
*   **Ring 0 (Kernelspace / Supervisor Mode):** Vòng trong cùng, quyền lực tuyệt đối. Mã chạy ở đây có thể làm mọi thứ, truy cập toàn bộ bộ nhớ và phần cứng.

> **Mục tiêu cuối cùng** của mọi cuộc tấn công leo thang đặc quyền (privilege escalation) là tìm cách thực thi mã từ Ring 3 lên Ring 0.

*   **Sự ra đời của Ring -1 (Hypervisor Mode - VMX):**
    Khi ảo hóa (Virtual Machines) trở nên phổ biến, một vấn đề nảy sinh: Kernel của máy ảo (guest OS) cũng muốn chạy ở Ring 0, nhưng nó không thể có quyền truy cập trực tiếp vào phần cứng thật của máy chủ (host OS).
    *   **Giải pháp cũ:** Ép kernel của máy ảo chạy ở Ring 1 và giả lập các lệnh Ring 0, rất chậm.
    *   **Giải pháp hiện đại (VT-x/AMD-V):** CPU giới thiệu một chế độ mới, gọi là Ring -1 (Hypervisor Mode). Hypervisor (phần mềm quản lý máy ảo) chạy ở đây. Nó có thể chặn các hành động nhạy cảm của guest OS (đang chạy ở Ring 0 "ảo") và xử lý chúng một cách an toàn.

## 4. Các mô hình Kernel

*   **Monolithic Kernel (Kernel nguyên khối - vd: Linux, FreeBSD):**
    Toàn bộ các thành phần cốt lõi của hệ điều hành (quản lý process, quản lý bộ nhớ, filesystem, network stack, drivers) đều nằm chung trong một không gian địa chỉ duy nhất ở Ring 0.
    > **Góc nhìn Hacker:** Trong monolithic kernel như Linux, driver là một phần của kernel. Một lỗi buffer overflow trong driver card đồ họa cũng có thể dẫn đến việc chiếm toàn bộ hệ thống. Đây là lý do tại sao driver là một **bề mặt tấn công (attack surface)** cực lớn.

*   **Microkernel (Kernel vi nhân - vd: Minix, seL4):**
    Kernel chỉ giữ lại những chức năng tối cần thiết nhất (giao tiếp giữa các tiến trình, quản lý cơ bản). Mọi thứ khác (drivers, filesystems) đều chạy dưới dạng các process riêng biệt ở Userspace (Ring 3). An toàn hơn nhưng có thể chậm hơn do phải giao tiếp nhiều.

*   **Hybrid Kernel (vd: Windows, macOS):**
    Kết hợp cả hai mô hình trên.

## 5. Chuyển đổi giữa các Ring: Cánh cổng `syscall`

Quá trình một chương trình từ Ring 3 "xin phép" Kernel ở Ring 0 diễn ra như sau:

**Chiều đi: Userspace (Ring 3) -> Kernel (Ring 0)**
1.  **Chuẩn bị:** Process ở userspace đặt mã định danh của system call (ví dụ, `__NR_read` là 0) vào thanh ghi `rax`, và các tham số khác vào `rdi`, `rsi`, `rdx`... theo quy ước.
2.  **Thực thi:** Process gọi lệnh `syscall`.
3.  **CPU tự động xử lý:**
    *   Chuyển quyền từ Ring 3 sang Ring 0.
    *   Lưu địa chỉ của lệnh kế tiếp trong userspace (giá trị của `rip`) vào thanh ghi `rcx`.
    *   Đọc địa chỉ của hàm xử lý từ `MSR_LSTAR` và nhảy `rip` đến đó.

**Chiều về: Kernel (Ring 0) -> Userspace (Ring 3)**
1.  **Hoàn tất:** Kernel xử lý xong yêu cầu.
2.  **Thực thi:** Kernel gọi lệnh `sysret`.
3.  **CPU tự động xử lý:**
    *   Chuyển quyền từ Ring 0 về lại Ring 3.
    *   Khôi phục lại `rip` từ giá trị đã lưu trong `rcx` để process ở userspace chạy tiếp.

> **Ghi chú quan trọng:** Trong suốt quá trình `syscall`, **"tấm bản đồ" bộ nhớ (Page Table do `cr3` trỏ tới) không hề thay đổi**. Process vẫn nhìn thấy bộ nhớ ảo của nó, chỉ có điều khi ở Ring 0, nó có thêm quyền truy cập vào vùng nhớ ảo cao của Kernel.

## 6. Lỗ hổng Kernel và Véc-tơ Tấn công

Code trong kernel cũng do con người viết, và nó cũng có lỗi! Các loại lỗ hổng quen thuộc như buffer overflow, use-after-free, race condition đều tồn tại trong kernel.

**Các hướng tấn công chính:**

*   **Từ Mạng (Network):** Kẻ tấn công từ xa gửi các gói tin được chế tạo đặc biệt để trigger lỗi trong network stack của kernel. Đây là loại lỗ hổng nguy hiểm nhất nhưng cũng hiếm nhất vì phần code này thường được audit cực kỳ kỹ lưỡng.
*   **Từ Userspace:** Một process cục bộ (có thể đang bị kẹt trong sandbox) gọi `syscall` hoặc `ioctl` với các tham số bất thường để khai thác lỗ hổng trong hàm xử lý của kernel. **Đây là con đường phổ biến nhất trong các cuộc thi CTF và để thoát khỏi sandbox (sandbox escape).**
*   **Từ Thiết bị (Devices):** Cắm một thiết bị USB giả mạo (như BadUSB) đã được lập trình để gửi dữ liệu sai chuẩn, gây ra lỗi trong driver xử lý USB của kernel.

**Ví dụ thực tế (Geekpwn 2016):**
Một nhóm hacker đã thực hiện một chuỗi exploit (exploit chain) để chiếm quyền hoàn toàn điện thoại Huawei P9:
1.  Root Android (chiếm quyền ở Userspace).
2.  Khai thác lỗi Kernel của Android (nhảy lên Ring 0).
3.  Từ Kernel, tấn công vào một ứng dụng chạy trong **TrustZone** (một môi trường thực thi an toàn, tách biệt ngay cả với kernel).
4.  Khai thác lỗi trong kernel của TrustZone.
5.  Kết quả cuối cùng: Ghi đè một module trong TrustZone để mở khóa điện thoại bằng... "dấu vân mũi" (Noseprint), chứng tỏ họ đã có toàn quyền kiểm soát hệ thống ở mức độ sâu nhất.
