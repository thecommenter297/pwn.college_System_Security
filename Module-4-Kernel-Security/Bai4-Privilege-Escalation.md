# Kernel Security 4: Privilege Escalation (Leo thang Đặc quyền)

Đây là mục tiêu tối thượng của hacker: bạn đang là một người dùng thường (user), và bạn muốn trở thành "siêu nhân" (root) - người có quyền lực tối cao trên hệ thống. Cách duy nhất để làm điều đó là lừa Kernel trao quyền cho bạn.

## 1. Bản chất của Kernel Vulnerabilities

Giống như slide đã nói, "Kernel code is just code". Nó vẫn mắc những lỗi lầm kinh điển như:

*   **Memory Corruptions:** Buffer Overflow, Use-After-Free, Double-Free, Integer Overflow.
*   **Race Conditions:** Đây là một vấn đề cực lớn trong Kernel. Vì Kernel luôn chạy đa luồng (multi-threaded), nhiều CPU có thể cùng lúc thực thi một đoạn mã driver. Nếu lập trình viên không sử dụng `mutex` (khóa) để bảo vệ các biến toàn cục, kẻ tấn công có thể tạo ra hai luồng (thread) cùng gọi vào một hàm `ioctl` để tạo ra các trạng thái không thể lường trước được, dẫn đến lỗi bộ nhớ.

**Sự khác biệt chết người:**
*   **Userspace:** Lỗi bộ nhớ -> Crash process -> Hệ điều hành dọn dẹp.
*   **Kernelspace:** Lỗi bộ nhớ -> Crash toàn bộ hệ thống (Kernel Panic) hoặc tệ hơn, bị hacker chiếm quyền điều khiển.

---

## 2. Kho báu của Hacker: `struct cred` và `task_struct`

Khi bạn chạy lệnh `whoami`, Kernel làm cách nào để biết bạn là ai? Mỗi một process đang chạy trên hệ thống đều được Kernel quản lý thông qua một cấu trúc dữ liệu khổng lồ tên là `task_struct`.

Hãy tưởng tượng `task_struct` như một tấm "Căn cước Công dân" của process. Bên trong đó, có một trường cực kỳ quan trọng:

```c
struct task_struct {
    // Rất nhiều trường khác...
    const struct cred __rcu *cred; // Con trỏ tới "ví tiền" chứa thông tin định danh
    // ...
};
```

Con trỏ `cred` này trỏ tới một cấu trúc khác, gọi là `struct cred`, chứa toàn bộ thông tin về quyền hạn của bạn:

```c
struct cred {
    kuid_t uid;   // User ID thực (Bạn là ai?)
    kgid_t gid;   // Group ID thực
    kuid_t euid;  // Effective User ID (Bạn đang có quyền của ai?)
    kgid_t egid;  // Effective Group ID
    kernel_cap_t cap_effective; // Các "siêu năng lực" (Capabilities)
    // ...
};
```
*   `uid=1000`: Người dùng thường.
*   `uid=0`: Người dùng **ROOT**.

> 🎯 **Kế hoạch tấn công kinh điển:** Nếu chúng ta tìm được một lỗ hổng cho phép **ghi đè bộ nhớ tùy ý (Arbitrary Write)**, chúng ta sẽ tìm địa chỉ của `struct cred` của process tấn công, sau đó **ghi số 0 vào tất cả các trường uid, gid, euid, egid...**. Ngay lập tức, process đó sẽ có quyền root!

---

## 3. "The Easy Way": `commit_creds(prepare_kernel_cred(0))`

Việc tự mình mò mẫm để ghi đè `struct cred` có thể phức tạp. May mắn thay, Kernel đã cung cấp sẵn một "con đường chính ngạch" cho các thành phần nội bộ của nó sử dụng để thay đổi quyền hạn:

*   **`prepare_kernel_cred(NULL)` hoặc `prepare_kernel_cred(0)`**:
    Hàm này giống như một "nhà máy sản xuất hộ chiếu". Khi bạn gọi nó với tham số `0` hoặc `NULL`, nó sẽ tạo ra một `struct cred` hoàn toàn mới, tinh khôi, với đầy đủ quyền lực của ROOT (`uid=0`, `gid=0`, và tất cả các `capabilities` đều được bật).

*   **`commit_creds(struct cred *)`**:
    Hàm này nhận một `struct cred` (ví dụ, cái vừa được tạo ra ở trên) và "đóng dấu", áp dụng nó cho process hiện tại đang chạy.

> 🔥 **Payload Vàng (The Golden Payload):**
> Chỉ cần thực thi được đúng một dòng C này trong Ring 0, bạn sẽ có ngay root:
> ```c
> commit_creds(prepare_kernel_cred(0));
> ```

---

## 4. (Đào sâu) The Hard Way - Kernel Heap Exploitation
*(Phần này slide gốc không đề cập nhưng là kiến thức cốt lõi của 90% các bài CTF Kernel hiện đại)*

Đa số lỗ hổng 0-day không cho bạn thực thi code ngay lập tức. Chúng chỉ cho bạn một lỗi bộ nhớ trên **Heap** (vùng nhớ cấp phát động), ví dụ như Use-After-Free (UAF) hoặc Heap Overflow.

**A. Sơ lược về Kernel Allocator (SLUB):**
Khi Kernel cần cấp phát các object nhỏ (như `struct cred`), nó dùng SLUB Allocator. SLUB quản lý các vùng nhớ ("slab") đã được chia sẵn thành các khối có kích thước cố định (vd: slab-32, slab-64, slab-128...). Khi một object được `kfree()`, con trỏ tới nó sẽ được đưa vào một `freelist` (danh sách các khối trống) để tái sử dụng sau này.

**B. Kỹ thuật tấn công UAF (Use-After-Free):**
1.  **Allocate & Free:** Kẻ tấn công tìm cách cấp phát một object (gọi là `victim_obj`) thông qua một syscall nào đó, rồi tìm cách `kfree()` nó, nhưng vẫn giữ lại được con trỏ tới nó (`stale pointer`). Lúc này, `victim_obj` đã nằm trong `freelist`.
2.  **Heap Spraying / Shaping (Tạo hình Heap):** Ngay lập tức, kẻ tấn công dùng một syscall khác để cấp phát hàng trăm object khác (gọi là `spray_obj`) có **cùng kích thước** với `victim_obj`. Theo cơ chế của SLUB, một trong các `spray_obj` này sẽ được cấp phát đè chính xác lên vùng nhớ của `victim_obj` cũ.
3.  **Overwrite:** Kẻ tấn công chế tạo `spray_obj` chứa dữ liệu độc hại. Ví dụ, nếu `victim_obj` cũ có một con trỏ hàm (`function_pointer`), thì bây giờ con trỏ hàm đó đã bị `spray_obj` ghi đè thành địa chỉ của shellcode!
4.  **Trigger:** Kẻ tấn công tìm cách khiến Kernel gọi lại con trỏ hàm đã bị ghi đè đó. Kết quả: **RIP (Instruction Pointer) bị chiếm quyền điều khiển!**

> **Ví dụ về các "Vật Tế Thần" (Elastic Objects) hay dùng để Spray:**
> *   `tty_struct`: Được dùng rất nhiều vì chứa một con trỏ hàm trong `tty_operations`.
> *   `msg_msg`: Dùng để leak địa chỉ và thực hiện arbitrary read/write vì nó cho phép đọc "out-of-bounds" một cách có kiểm soát.
> *   `user_key_payload`: Một object kinh điển khác để thực hiện UAF.

---

## 5. Thách thức: Làm sao tìm được địa chỉ? (kASLR)

Dù bạn dùng cách dễ (`commit_creds`) hay cách khó (Heap), bạn đều phải đối mặt với một vấn đề: **kASLR (Kernel Address Space Layout Randomization)**.

Mỗi khi hệ thống khởi động, Kernel sẽ được nạp vào một địa chỉ gốc (base address) ngẫu nhiên. Điều này có nghĩa là địa chỉ của `commit_creds`, `prepare_kernel_cred`, và các ROP gadget sẽ thay đổi liên tục.

**Giải pháp:** Bạn phải tìm một lỗi **Information Leak (Rò rỉ thông tin)**.
*   **Leak con trỏ Kernel:** Tìm một lỗ hổng (ví dụ, lỗi logic trong `ioctl` hoặc UAF chưa được dọn dẹp) khiến Kernel gửi trả về cho Userspace một vài byte chứa địa chỉ của một hàm hoặc một cấu trúc dữ liệu nào đó trong Kernel.
*   **Tính toán Offset:** Một khi bạn đã có một địa chỉ rò rỉ (leak address), bạn có thể tính ra địa chỉ gốc của Kernel bằng cách:
    `Kernel Base = Leaked Address - Offset của hàm/biến đó`
    (Offset này bạn có thể lấy từ file `vmlinux` hoặc `/proc/kallsyms` trên một hệ thống giống hệt nhưng đã tắt kASLR).

Sau khi có Kernel Base, bạn có thể tính ra địa chỉ của mọi thứ bạn cần!

---
**Tóm tắt cho GitHub:**
Privilege Escalation trong Kernel xoay quanh việc ghi đè các cấu trúc dữ liệu quản lý quyền hạn. Có hai hướng chính:
1.  **Tấn công trực tiếp (Direct Attack):** Nếu có lỗ hổng cho phép thực thi mã hoặc ghi đè tùy ý, hãy gọi `commit_creds(prepare_kernel_cred(0))` để có Root ngay lập tức.
2.  **Tấn công gián tiếp qua Heap (Heap Exploitation):** Sử dụng các lỗi như UAF/Double-Free, kết hợp với kỹ thuật Heap Spraying để ghi đè con trỏ hàm trong các object của Kernel, từ đó chiếm quyền điều khiển thực thi (RIP control).

Cả hai cách đều đòi hỏi phải vượt qua **kASLR** bằng một lỗi rò rỉ thông tin (Info Leak).
