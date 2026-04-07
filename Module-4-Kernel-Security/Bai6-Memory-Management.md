# Kernel Security 6: Quản lý Bộ nhớ

Mọi cuộc tấn công vào Kernel đều xoay quanh bộ nhớ. Để có thể đọc/ghi/thực thi mã trong Kernel, trước tiên, bạn phải hiểu cách Kernel và CPU tổ chức và bảo vệ bộ nhớ. Đây là nền tảng của mọi kỹ thuật exploit và mitigation.

## 1. Vấn đề: Sự hỗn loạn của Bộ nhớ Vật lý (Physical Memory)

Hãy tưởng tượng RAM vật lý trong máy tính của bạn là một con đường thẳng tắp, dài vô tận, được đánh địa chỉ từ `0x0` trở đi. Bây giờ, nếu không có cơ chế quản lý nào, hệ điều hành sẽ nạp các chương trình vào con đường này như thế nào?

Giả sử:
*   Chương trình A (ví dụ: `cat`) được nạp vào địa chỉ `0x1000`.
*   Chương trình B (ví dụ: `ls`) được nạp vào địa chỉ `0x5000`.

Sẽ có 3 vấn đề chí mạng xảy ra:

1.  **Xung đột (Collision):** Nếu chương trình C cũng muốn được nạp vào địa chỉ `0x1000` (vì nó được lập trình như vậy), hệ thống sẽ sụp đổ.
2.  **Phân mảnh (Fragmentation):** Nếu chương trình A chạy xong và được gỡ bỏ, nó để lại một "lỗ hổng" 4KB tại `0x1000`. Nếu chương trình D cần 8KB bộ nhớ, nó sẽ không thể chui vừa vào lỗ hổng đó, gây lãng phí tài nguyên.
3.  **Không có sự cô lập (No Isolation) - Vấn đề An ninh Nghiêm trọng nhất:** Chương trình A có thể tính toán và ghi một giá trị vào địa chỉ `0x5010`. Địa chỉ này đang thuộc về chương trình B! Chương trình A có thể đọc trộm dữ liệu, hoặc tệ hơn, ghi đè mã nguồn của chương trình B để chiếm quyền điều khiển nó. **Đây là một thảm họa bảo mật.**

## 2. Giải pháp: Virtual Memory - Bậc thầy của những ảo ảnh

Để giải quyết triệt để các vấn đề trên, các hệ điều hành hiện đại không cho phép process truy cập trực tiếp vào bộ nhớ vật lý. Thay vào đó, mỗi process được cấp một **không gian địa chỉ ảo (Virtual Address Space)** riêng.

Hãy tưởng tượng thế này:
*   **Bộ nhớ vật lý (RAM):** Là một thành phố có thật với những tòa nhà ở những vị trí cụ thể.
*   **Mỗi process:** Là một du khách.
*   **Không gian địa chỉ ảo:** Là một tấm bản đồ du lịch **giả** mà hệ điều hành phát cho mỗi du khách.

Điều đặc biệt là **mọi tấm bản đồ đều giống hệt nhau**. Trên bản đồ nào cũng có "Quảng trường trung tâm" ở địa chỉ `0x400000`, "Thư viện Quốc gia" ở địa chỉ `0x7f...`. Du khách (process) chỉ cần đi theo tấm bản đồ của mình.

Nhiệm vụ của **Hệ điều hành** và **Phần cứng (MMU - Memory Management Unit)** là bí mật dịch địa chỉ trên tấm bản đồ giả (địa chỉ ảo) sang vị trí thực tế trong thành phố (địa chỉ vật lý).

> **Lợi ích của Virtual Memory:**
> 1.  **Cô lập tuyệt đối:** "Quảng trường trung tâm" trên bản đồ của du khách A có thể được dịch ra tòa nhà ở `0x1234000` trong thành phố thật. Nhưng "Quảng trường trung tâm" trên bản đồ của du khách B lại được dịch ra một tòa nhà hoàn toàn khác ở `0x5678000`. A không bao giờ có thể "đi lạc" sang khu vực của B.
> 2.  **Ảo ảnh liền mạch:** Du khách A nghĩ rằng mình có một vùng đất rộng 8KB liền nhau trên bản đồ. Nhưng trên thực tế, hệ điều hành có thể cấp cho A hai mảnh đất 4KB nằm ở hai đầu khác nhau của thành phố. Điều này giải quyết hoàn toàn vấn đề phân mảnh.
> 3.  **Lập trình đơn giản:** Lập trình viên và trình biên dịch không cần quan tâm chương trình sẽ được nạp vào đâu trong RAM thật. Họ có thể mặc định rằng code luôn bắt đầu ở `0x400000`, stack luôn ở cuối vùng nhớ...

## 3. Pages và Frames: Những viên gạch xây nên bộ nhớ

Việc dịch từng byte một từ ảo sang vật lý là bất khả thi. Thay vào đó, MMU chia bộ nhớ thành những khối có kích thước cố định.

*   **Page:** Một khối bộ nhớ **ảo** có kích thước cố định.
*   **Frame:** Một khối bộ nhớ **vật lý** có kích thước cố định.

Kích thước của Page và Frame luôn bằng nhau. Trên x86-64, kích thước tiêu chuẩn là **4KB (4096 bytes, hay 0x1000 hex)**.

Một địa chỉ ảo bất kỳ sẽ được chia làm 2 phần:
*   **Virtual Page Number (VPN):** Số hiệu của trang ảo.
*   **Page Offset:** Vị trí của byte bên trong trang đó.

Ví dụ, với page size là 4KB (0x1000), địa chỉ ảo `0x12345` sẽ được hiểu là:
*   `0x12` là VPN (Vì `0x12 * 0x1000 = 0x12000`).
*   `0x345` là Offset.

Nhiệm vụ của MMU là dịch **VPN** thành **Physical Frame Number (PFN)**, sau đó giữ nguyên **Offset**.

## 4. Page Table: Tấm bản đồ đầu tiên (Mô hình đơn cấp)

Để thực hiện việc dịch địa chỉ, MMU cần một "sổ tay" tra cứu. Sổ tay này được gọi là **Page Table**.

Mô hình đơn giản nhất là một mảng khổng lồ.
*   **Index** của mảng chính là **VPN**.
*   **Giá trị** tại index đó là **PFN**.

*(Trong hình, địa chỉ ảo có VPN=2 được dịch sang địa chỉ vật lý có PFN=7)*

**Quá trình dịch địa chỉ (Mô hình đơn cấp):**
1.  CPU muốn truy cập địa chỉ ảo `0x2ABC`.
2.  MMU tách địa chỉ ra: VPN = `0x2`, Offset = `0xABC`.
3.  MMU truy cập Page Table tại index `2`.
4.  Nó đọc được giá trị PFN là `7`.
5.  MMU ghép PFN và Offset lại: `0x7` + `0xABC` = `0x7ABC`.
6.  CPU sẽ truy cập vào địa chỉ vật lý `0x7ABC`.

## 5. Sự sụp đổ của mô hình đơn cấp

Mô hình này trông rất đơn giản và hiệu quả, nhưng nó có một lỗ hổng chí mạng khi áp dụng vào kiến trúc 64-bit: **kích thước của chính Page Table**.

Hãy làm một phép toán:
*   Một địa chỉ 64-bit có thể đánh dấu 2^64 byte.
*   Trang có kích thước 4KB (2^12 bytes).
*   Vậy chúng ta có 2^64 / 2^12 = **2^52** trang ảo khác nhau.
*   Mỗi entry trong Page Table để lưu PFN và các cờ bảo mật cần 8 byte (64-bit).
*   Tổng kích thước của Page Table = 2^52 * 8 bytes = **32 Petabytes (PB)**!

Bạn không thể lưu một "cuốn sổ" tra cứu nặng 32 Petabyte vào RAM chỉ để quản lý bộ nhớ! Hơn nữa, toàn bộ Page Table này phải nằm **liền mạch** trong bộ nhớ vật lý, điều này là không tưởng.

Chính vì sự bất khả thi này, các kỹ sư phần cứng đã phát minh ra một giải pháp cực kỳ thông minh và thanh lịch, đó là **Page Table đa cấp (Multi-Level Paging)**.

## 6. Cấu trúc Page Table đa cấp (Multi-Level Paging)

Trên kiến trúc x86-64, hệ thống này có 4 cấp độ, giống như một cấu trúc thư mục lồng nhau. Mỗi cấp là một "bảng" (một page 4KB) chứa 512 "entry". Mỗi entry trỏ xuống cấp tiếp theo.

```
                  +------------------+
CR3 Register ---> |       PML4       |  (Page Map Level 4)
                  | (512 entries)    |
                  +--------|---------+
                           |
            +--------------v--------------+
            |      PDPT (Page Directory   |
            |      Pointer Table)         |
            |      (512 entries)          |
            +--------------|--------------+
                           |
            +--------------v--------------+
            |      PD (Page Directory)    |
            |      (512 entries)          |
            +--------------|--------------+
                           |
            +--------------v--------------+
            |      PT (Page Table)        |
            |      (512 entries)          |
            +--------------|--------------+
                           |
                           v
                     +-----------+
                     | Physical  |
                     |   Frame   |
                     |   (4KB)   |
                     +-----------+
```

**Mỗi cấp quản lý một vùng không gian địa chỉ khổng lồ:**

*   **Page Table (PT):** Cấp cuối cùng. Mỗi entry trong nó trỏ trực tiếp đến một Frame vật lý 4KB. Một Page Table có 512 entry, vậy nó quản lý `512 * 4KB = 2MB` bộ nhớ.
*   **Page Directory (PD):** Mỗi entry trong nó trỏ tới một Page Table. Một Page Directory quản lý `512 * 2MB = 1GB` bộ nhớ.
*   **Page Directory Pointer Table (PDPT):** Mỗi entry trỏ tới một Page Directory. Một PDPT quản lý `512 * 1GB = 512GB` bộ nhớ.
*   **Page Map Level 4 (PML4):** Cấp cao nhất. Mỗi entry trỏ tới một PDPT. Một PML4 quản lý `512 * 512GB = 256TB` bộ nhớ.

**Tại sao nó hiệu quả?** Nếu một ứng dụng chỉ dùng vài MB bộ nhớ, hệ điều hành chỉ cần cấp phát một PML4, một PDPT, một PD và một vài PT. Phần lớn các entry trong các bảng cấp cao sẽ là `NULL`, không tốn một byte RAM nào cho các vùng nhớ không sử dụng.

## 7. Giải phẫu một Địa chỉ ảo 64-bit

Mặc dù được gọi là kiến trúc 64-bit, các CPU x86-64 hiện tại chỉ sử dụng **48 bit** cho việc đánh địa chỉ ảo (lý do là 2^64 là một con số quá lớn và không thực tế, 48 bit cho phép đánh địa chỉ 256TB là quá đủ trong nhiều năm tới).

Một địa chỉ ảo 48-bit hợp lệ (canonical address) sẽ được chia thành các phần như sau:

```
+-----------+--------+--------+--------+--------+--------------+
|   16 bits | 9 bits | 9 bits | 9 bits | 9 bits |    12 bits   |
+-----------+--------+--------+--------+--------+--------------+
| Sign Ext. | Index  | Index  | Index  | Index  | Page Offset  |
|  (Unused) |  PML4  |  PDPT  |   PD   |   PT   |              |
```

*   **12 bit cuối (Offset):** Vị trí của byte bên trong một page 4KB (`2^12 = 4096`). Phần này **không bao giờ bị dịch**, nó được giữ nguyên.
*   **9 bit tiếp theo (PT Index):** Chỉ số (từ 0-511) để tra cứu trong Page Table.
*   **9 bit tiếp theo (PD Index):** Chỉ số để tra cứu trong Page Directory.
*   **9 bit tiếp theo (PDPT Index):** Chỉ số để tra cứu trong PDPT.
*   **9 bit tiếp theo (PML4 Index):** Chỉ số để tra cứu trong PML4.
*   **16 bit đầu:** Phải là bản sao của bit thứ 47 (sign extension). Các địa chỉ không tuân thủ quy tắc này sẽ gây ra lỗi #GP (General Protection Fault). Đây là lý do tại sao vùng nhớ userspace bắt đầu từ `0x0000...` và vùng nhớ kernel bắt đầu từ `0xFFFF...`.

**Quá trình dịch địa chỉ đầy đủ (The Page Walk):**
Khi CPU cần truy cập địa chỉ ảo, MMU (Memory Management Unit) sẽ thực hiện một "cuộc đi bộ" qua 4 cấp bảng:
1.  Đọc địa chỉ vật lý của PML4 từ thanh ghi `CR3`.
2.  Dùng `PML4 Index` từ địa chỉ ảo để tìm entry trong PML4, lấy ra địa chỉ vật lý của PDPT.
3.  Dùng `PDPT Index` để tìm entry trong PDPT, lấy ra địa chỉ vật lý của PD.
4.  Dùng `PD Index` để tìm entry trong PD, lấy ra địa chỉ vật lý của PT.
5.  Dùng `PT Index` để tìm entry trong PT, lấy ra địa chỉ vật lý của **Frame (PFN)**.
6.  Ghép địa chỉ Frame vật lý với `Page Offset` để có được địa chỉ vật lý cuối cùng.

## 8. Page Table Entry (PTE): Trái tim của Bảo mật Bộ nhớ

Một entry trong Page Table không chỉ chứa địa chỉ của cấp tiếp theo. Nó còn chứa một loạt các **cờ (flags)** bảo mật được kiểm tra **bằng phần cứng** ở mỗi lần truy cập bộ nhớ. Đây chính là nền tảng vật lý của các cơ chế bảo vệ như SMEP, SMAP, và NX.

Một Page Table Entry (PTE) 64-bit có cấu trúc như sau:

```
+---+----------+----------+---+---+---+---+---+---+---+---+--------------+
|XD | ignored  | available| G |...| D | A |...|U/S|R/W| P | PFN          |
+---+----------+----------+---+---+---+---+---+---+---+---+--------------+
 63                                     12 11       2   1   0            47-12
```

**Các cờ bảo mật quan trọng nhất:**

*   **P (Present Bit - bit 0):**
    *   `1`: Trang này đang có mặt trong RAM vật lý.
    *   `0`: Trang này không có trong RAM (có thể nó đã bị đẩy ra ổ cứng - swap). Nếu truy cập, CPU sẽ gây ra một **Page Fault**, trao quyền cho HĐH để nạp trang này từ đĩa vào RAM.

*   **R/W (Read/Write Bit - bit 1):**
    *   `0`: Trang này chỉ được phép đọc (Read-Only).
    *   `1`: Trang này được phép đọc và ghi.
    > 🔥 **Ứng dụng:** Vùng nhớ chứa mã nguồn (`.text`) và dữ liệu hằng (`.rodata`) của một chương trình sẽ có bit R/W được set thành 0 để chống ghi đè.

*   **U/S (User/Supervisor Bit - bit 2):**
    *   `0`: **Supervisor Mode only**. Chỉ mã lệnh đang chạy ở Ring 0 (Kernel) mới được phép truy cập trang này.
    *   `1`: **User Mode access allowed**. Mã lệnh ở cả Ring 0 và Ring 3 đều có thể truy cập.
    > 🔥 **Ứng dụng (Nền tảng của SMEP/SMAP):** Đây là cờ quan trọng nhất để cách ly Kernel và Userspace. Nếu một process ở Ring 3 cố gắng truy cập vào một trang có cờ U/S=0, CPU sẽ ngay lập tức gây ra lỗi bảo vệ (#GP). SMEP và SMAP là các cơ chế nâng cao dựa trên cờ này để ngăn Kernel (Supervisor) truy cập ngược lại trang của User một cách không an toàn.

*   **XD (Execute-Disable Bit - bit 63, còn gọi là NX - No-eXecute):**
    *   `1`: **Không được phép thực thi**. CPU sẽ từ chối chạy mã lệnh từ trang này.
    *   `0`: Được phép thực thi.
    > 🔥 **Ứng dụng (Nền tảng của W^X):** Đây là mitigation chống lại các cuộc tấn công phun shellcode kinh điển. Các vùng nhớ dữ liệu như Stack và Heap sẽ luôn được đánh dấu là NX=1. Điều này buộc hacker phải sử dụng các kỹ thuật tấn công phức tạp hơn như **Return-Oriented Programming (ROP)**.
