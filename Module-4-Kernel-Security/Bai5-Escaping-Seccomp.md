# Kernel Security 5: Vượt ngục Seccomp (Escaping Seccomp)

Đây không chỉ là một kỹ thuật, mà là **đỉnh cao của nghệ thuật tấn công**, nơi một lỗi ở tầng sâu nhất (Kernel) được dùng để phá vỡ lớp bảo vệ ở tầng cao hơn (Sandbox). Hơn 30 sandbox escape của Google Chrome trong năm 2019 đều đi theo con đường này.

## 1. Ôn lại về Seccomp: Nhà tù số của Linux

Hãy tưởng tượng bạn chạy một chương trình không đáng tin cậy (ví dụ, một tab trình duyệt đang render một trang web lạ). Bạn không muốn nó có thể tự do đọc file `/etc/passwd` hay mở kết nối mạng tùy tiện.

**Seccomp (Secure Computing Mode)** là một cơ chế an ninh của Linux Kernel cho phép một process tự "khóa tay" chính mình. Nó nói với Kernel rằng: *"Kể từ bây giờ, tôi chỉ được phép sử dụng một danh sách các system call cực kỳ hạn chế (ví dụ: chỉ `read`, `write`, `exit`). Nếu tôi cố tình gọi bất kỳ syscall nào khác ngoài danh sách này, hãy giết tôi ngay lập tức."*

Đây là lớp phòng thủ cuối cùng. Ngay cả khi hacker đã chiếm được quyền thực thi mã trong process bị sandbox (ví dụ, thông qua một lỗi RCE trong trình duyệt), chúng vẫn bị kẹt trong một cái lồng số, không thể làm gì nguy hại đến hệ thống vì mọi syscall nguy hiểm (`open`, `execve`, `socket`...) đã bị cấm.

> **Thực tế:** Các sandbox hiện đại như của Chrome hay Docker không cấm hoàn toàn, mà sử dụng một chế độ nâng cao gọi là `seccomp-bpf`. Chế độ này cho phép định nghĩa các quy tắc phức tạp hơn (ví dụ: "cho phép `open()` nhưng chỉ với file có đuôi `.tmp`").

## 2. Điểm yếu chết người của Seccomp

Slide đã chỉ ra một chân lý tàn nhẫn:
> **"Dù bị khóa trong lồng, tù nhân vẫn có thể nói chuyện với cai ngục."**

Process bị sandbox vẫn có thể gọi các system call "vô hại" được cho phép trong danh sách trắng (whitelist). Và chính những syscall này lại là **bề mặt tấn công (attack surface)** để hacker chọc vào Kernel.

Nếu một trong những syscall được phép đó có chứa một lỗ hổng (ví dụ: một `ioctl` xử lý sai tham số), hacker có thể trigger lỗ hổng đó để giành quyền thực thi mã trong **Ring 0**.

Và khi bạn đã ở Ring 0, bạn chính là "cai ngục". Bạn có thể tự mở khóa cho chính mình.

## 3. Phẫu thuật cấu trúc `task_struct` để gỡ bỏ Seccomp

Làm thế nào Kernel biết một process đang bị Seccomp giám sát? Câu trả lời lại nằm trong "Căn cước Công dân" `task_struct`.

```c
struct task_struct {
    // ...
    const struct cred __rcu *cred;
    struct thread_info thread_info; // Chứa các thông tin cấp thấp của luồng
    // ...
};
```

Bên trong `task_struct` là một struct khác tên là `thread_info`. Và trong `thread_info` có một trường gọi là `flags`:

```c
struct thread_info {
    unsigned long flags; // Một bitfield chứa các cờ trạng thái
    // ...
};
```

Trường `flags` này là một tập hợp các bit, mỗi bit đại diện cho một trạng thái đặc biệt của luồng. Một trong những bit đó có tên là `TIF_SECCOMP` (Thread Info Flag SECCOMP).

*   Nếu bit `TIF_SECCOMP` được **bật (set thành 1)**, mỗi khi process thực hiện syscall, Kernel sẽ kiểm tra các quy tắc của Seccomp.
*   Nếu bit `TIF_SECCOMP` được **tắt (set thành 0)**, Kernel sẽ bỏ qua hoàn toàn việc kiểm tra Seccomp!

> 🔥 **Kế hoạch vượt ngục:**
> 1.  Tìm một lỗi Kernel (ví dụ: UAF, buffer overflow...) từ một syscall được phép.
> 2.  Khai thác lỗi đó để có khả năng **ghi đè bộ nhớ tùy ý (Arbitrary Write)** trong Ring 0.
> 3.  Tìm địa chỉ của `task_struct` của chính process tấn công.
> 4.  Tính toán offset để trỏ tới trường `thread_info.flags`.
> 5.  Ghi đè bit `TIF_SECCOMP` về 0.
> 6.  Xong! Kể từ syscall tiếp theo, process đã được "tự do", có thể gọi `execve("/bin/sh")` để mở shell.

## 4. Làm sao tìm `current_task_struct` trong Shellcode?

Đây là một câu hỏi cực kỳ quan trọng. Kernel cần một cách hiệu quả để truy cập vào `task_struct` của process đang chạy trên CPU hiện tại.

Trên kiến trúc x86-64, Kernel đã tận dụng một thanh ghi đặc biệt: **thanh ghi segment `GS`**.

Khi một syscall được thực hiện và CPU chuyển sang Ring 0, Kernel sẽ thiết lập thanh ghi `GS` để trỏ tới một vùng nhớ đặc biệt chứa thông tin của CPU đó (`per-cpu` data). Ở một offset cố định trong vùng nhớ này chính là con trỏ tới `current_task_struct`.

Kernel cung cấp một macro trong C là `current` để tự động hóa việc này. Nhưng trong Assembly/Shellcode, chúng ta phải làm thủ công:

```assembly
; Đoạn mã Assembly để lấy địa chỉ của task_struct hiện tại
mov rax, gs:[offset_to_current_task_struct]
```

Giá trị `offset_to_current_task_struct` này có thể thay đổi giữa các phiên bản Kernel, nhưng thường là một hằng số có thể tìm thấy bằng cách debug hoặc phân tích mã nguồn.

> **Thủ thuật cho CTF:** Bạn không cần phải nhớ offset này. Cách tốt nhất, là viết một module C nhỏ in ra `&current->thread_info.flags`, biên dịch và disassemble nó để xem compiler đã sinh ra mã assembly như thế nào, sau đó copy-paste logic đó vào shellcode của bạn.

## 5. Kịch bản tấn công hoàn chỉnh

1.  **Giai đoạn 1: Chuẩn bị (Userspace)**
    *   Hacker tìm thấy một lỗi RCE trong một trình duyệt (ví dụ) và chạy được shellcode trong một tab sandbox.
    *   Shellcode này bị Seccomp khóa lại, chỉ có thể gọi vài syscall như `read`, `write`, `ioctl`...

2.  **Giai đoạn 2: Leo thang (Kernel Exploit)**
    *   Shellcode ở userspace chuẩn bị các tham số độc hại và gọi một `ioctl` được phép.
    *   `ioctl` này có lỗi UAF, cho phép hacker chiếm quyền điều khiển RIP trong Kernel (thông qua KROP chain).

3.  **Giai đoạn 3: Vượt ngục (Kernel Payload)**
    *   KROP chain trong Kernel thực thi một đoạn mã ngắn (kernel shellcode) làm các việc sau:
        *   Lấy địa chỉ của `current_task_struct` qua thanh ghi `GS`.
        *   Tính toán địa chỉ của `&current->thread_info.flags`.
        *   Thực hiện một phép toán logic để xóa bit `TIF_SECCOMP`: `flags &= ~(1 << TIF_SECCOMP_BIT_POSITION)`.
        *   Return an toàn về lại Userspace.

4.  **Giai đoạn 4: Tự do**
    *   Shellcode ở userspace bây giờ đã được "phá còng". Nó thực thi một lệnh `execve("/bin/sh", NULL, NULL)`.
    *   Vì `TIF_SECCOMP` đã bị tắt, Kernel không còn kiểm tra nữa và một root shell được mở ra!

**Lưu ý:** Kỹ thuật này chỉ vô hiệu hóa Seccomp cho process hiện tại. Các process con (child process) được sinh ra sau đó có thể vẫn bị áp dụng Seccomp do các cấu hình khác trong Kernel. Tuy nhiên, khi bạn đã có shell, việc đó không còn quan trọng nữa.

---
**Tóm tắt cho GitHub:**
Seccomp là một cơ chế sandbox mạnh mẽ, nhưng nó không thể bảo vệ chính Kernel. Bằng cách khai thác một lỗ hổng trong các syscall được Seccomp cho phép, kẻ tấn công có thể nhảy vào Ring 0. Từ đó, payload trong Kernel sẽ tìm đến `task_struct` của process tấn công (thông qua thanh ghi `GS`) và tắt cờ `TIF_SECCOMP`. Hành động này giống như một "cai ngục" tự tay mở khóa cho tù nhân, vô hiệu hóa hoàn toàn sandbox và cho phép thực thi mã tùy ý trên hệ thống.
