# Kernel Security 3: Kernel Modules (LKM)

Khi bạn muốn thêm một tính năng mới vào Linux Kernel (ví dụ: Driver cho một chiếc webcam mới mua), bạn có hai lựa chọn:
1. Sửa mã nguồn Kernel, biên dịch lại toàn bộ hệ điều hành (mất hàng giờ đồng hồ) và khởi động lại máy.
2. Viết một **Loadable Kernel Module (LKM)**, biên dịch nó trong vài giây, và nạp nó vào hệ điều hành ngay lập tức mà không cần khởi động lại.

Tất nhiên, lựa chọn 2 tối ưu hơn. Trong thế giới CTF và săn lỗ hổng (Vulnerability Hunting), **99% các bài tập và lỗ hổng thực tế nằm ở các Kernel Module (Driver) này**, chứ hiếm khi nằm ở nhân lõi (Core Kernel).

---

## 1. Bản chất của một Kernel Module

Hãy so sánh sự tương đồng giữa Userspace và Kernelspace:

| Đặc điểm | Userspace | Kernelspace |
| :--- | :--- | :--- |
| **Thư viện chia sẻ** | File `.so` (Dynamic Link Library) | File `.ko` (Kernel Object) |
| **Định dạng file** | ELF (Executable and Linkable Format) | ELF (Nhưng được thiết kế cho Kernel) |
| **Quyền lực** | Ring 3 (Bị giới hạn gắt gao) | Ring 0 (Toàn quyền sinh sát) |
| **Bộ nhớ** | Vùng nhớ ảo thấp | Vùng nhớ ảo cao |

Khi một module `.ko` được nạp vào nhân hệ điều hành, nó **trở thành một phần của Kernel**. Nó chia sẻ chung không gian địa chỉ bộ nhớ với Kernel. Một lỗi crash trong module sẽ đánh sập toàn bộ hệ thống (Kernel Panic).

---

## 2. Các phương thức giao tiếp của Module (Cách Hacker chạm vào Kernel)

Một Module nằm im trong Kernel không có giá trị gì nếu người dùng (Userspace) không thể giao tiếp với nó. Có 3 cách chính để giao tiếp:

### A. Qua System Calls (Lịch sử)
Ngày xưa, module có thể trực tiếp ghi đè bảng Syscall Table để tạo ra một syscall mới (ví dụ: `syscall 999`). Trên các Linux Kernel hiện đại, bảng này đã bị khóa chết (Read-Only) để chống Rootkit. Việc thay đổi Syscall Table hiện nay không còn được hỗ trợ chính thức.

### B. Qua Interrupts (Ngắt)
Module có thể đăng ký xử lý một mã ngắt cụ thể (như `int3` hoặc Invalid Opcode Exception). Thường được dùng cho các giải pháp bảo mật nâng cao hoặc anti-cheat, nhưng hiếm khi được dùng làm cổng giao tiếp chuẩn cho ứng dụng.

### C. Qua File (Cực kỳ phổ biến - Mỏ vàng của Hacker!)
Hệ tư tưởng của Linux là: *"Mọi thứ đều là file"*. Để người dùng gọi được module, module sẽ tạo ra một file ảo ở các thư mục:
*   `/dev` (Device files): Chủ yếu cho phần cứng (ví dụ: `/dev/tty`, `/dev/nvme0`).
*   `/proc` (Process Information): Ban đầu dùng để hiển thị thông tin tiến trình, sau này bị lạm dụng làm giao diện cấu hình Kernel.
*   `/sys` (System Information): Giao diện sạch sẽ hơn để cấu hình thiết bị.

---

## 3. Khai quật `file_operations` (Bề mặt tấn công số 1)

Khi Module tạo ra một file ở `/dev/pwn_device`, làm sao Kernel biết khi người dùng gõ lệnh `cat /dev/pwn_device` thì phải làm gì? 

Câu trả lời nằm ở struct `file_operations` (thường gọi tắt là **fops**). Đây là một bảng chứa các con trỏ hàm (Function Pointers). Lập trình viên sẽ đăng ký xem file của họ hỗ trợ những hành động gì:

```c
// Ví dụ về cấu trúc file_operations trong Kernel Module
static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = device_open,    // Gọi khi user dùng open()
    .read           = device_read,    // Gọi khi user dùng read()
    .write          = device_write,   // Gọi khi user dùng write()
    .unlocked_ioctl = device_ioctl,  // Cổng điều khiển vạn năng (Rất quan trọng!)
    .release        = device_release, // Gọi khi user dùng close()
};
```

> 🎯 **Tư duy Săn 0-day/CTF:** Khi bạn đảo ngược một file `.ko` (Kernel Module) trong IDA Pro, việc đầu tiên bạn cần làm là **tìm kiếm struct `file_operations` này**. Nó chính là tấm bản đồ chỉ ra tất cả các hàm mà bạn (từ Userspace) có thể kích hoạt!

---

## 4. `ioctl` (Input-Output Control) - Cánh cổng vạn năng của Bugs

Trong khi `read` và `write` chỉ xử lý các luồng dữ liệu tuần tự (như đọc/ghi file văn bản), thì phần cứng đòi hỏi nhiều hơn thế. Ví dụ, bạn muốn chỉnh độ phân giải của Webcam lên 1080p, bạn không thể dùng `write` văn bản vào camera được. Bạn cần ra lệnh.

Đó là lúc `ioctl` xuất hiện. Cú pháp phía Userspace:

```c
int fd = open("/dev/pwn_device", O_RDWR);
// Gửi COMMAND_CODE kèm theo một cấu trúc dữ liệu tùy chỉnh
ioctl(fd, COMMAND_CODE, &my_data_struct); 
```

Phía Kernel Space sẽ tiếp nhận như sau:

```c
static long device_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param) {
    switch (ioctl_num) {
        case CMD_SET_RESOLUTION:
            // Đọc dữ liệu từ `ioctl_param` và xử lý...
            break;
        case CMD_RESET_DEVICE:
            // Khởi động lại thiết bị...
            break;
        default:
            return -EINVAL; // Lệnh không hợp lệ
    }
}
```

> 🔥 **Tại sao `ioctl` là ổ khóa chứa nhiều Bug 0-day nhất?**
> Bởi vì logic trong câu lệnh `switch-case` của các driver bên thứ ba (NVIDIA, Card Wifi, driver IoT...) thường được viết rất cẩu thả. Lập trình viên thường quên kiểm tra kích cỡ dữ liệu người dùng gửi lên, dẫn đến các lỗi kinh điển như **Stack Buffer Overflow** hoặc **Integer Overflow** ngay trong Ring 0!

---

## 5. Cầu nối an toàn: `copy_to_user` và `copy_from_user`

Bởi vì bộ nhớ của Userspace (Ring 3) và Kernelspace (Ring 0) tách biệt, Kernel tuyệt đối không được dùng con trỏ của Userspace một cách trực tiếp. 

Ví dụ, nếu kẻ tấn công gửi một con trỏ userspace `0x1337000` vào Kernel thông qua `ioctl`, và Kernel cứ thế dùng lệnh `memcpy` trực tiếp lên con trỏ đó, kẻ tấn công có thể cố tình giải phóng (free) vùng nhớ đó ở Userspace giữa chừng, gây ra lỗi crash hệ thống.

Để bảo vệ hệ thống, Linux cung cấp hai hàm chuẩn bắt buộc phải dùng:

1.  **`copy_from_user(kernel_buf, user_buf, size)`**: Lấy dữ liệu từ Userspace chép vào bộ nhớ Kernel một cách an toàn.
2.  **`copy_to_user(user_buf, kernel_buf, size)`**: Chép dữ liệu từ Kernel trả về cho Userspace một cách an toàn.

Hai hàm này không chỉ đơn thuần là `memcpy`. Chúng thực hiện kiểm tra xem địa chỉ `user_buf` có thực sự thuộc quyền quản lý của Userspace hay không, và nó có hợp lệ tại thời điểm truy cập không.

> ⚠️ **Lỗ hổng Arbitrary Read/Write (Đọc ghi tùy ý) khi thiếu kiểm tra:**
> Nếu một lập trình viên viết driver lười biếng, thay vì dùng hai hàm trên, họ lại viết như thế này:
> ```c
> // ĐÂY LÀ BUG CỰC NẶNG!
> long *vulnerable_ptr = (long *)ioctl_param;
> *vulnerable_ptr = kernel_secret_variable; // Kernel tự ghi vào bất kỳ địa chỉ nào user đưa vào!
> ```
> Nếu không dùng `copy_to_user/from_user`, Hacker có thể lừa Kernel ghi đè (Write) hoặc đọc trộm (Read) vào **bất kỳ địa chỉ bộ nhớ nào của Kernel** (ví dụ ghi đè cấu trúc `cred` để lấy Root!).

---

## 6. Tổng hợp các lệnh quản lý Module (Copy-paste)

Để tương tác với các module trong quá trình debug, bạn sẽ sử dụng các lệnh Terminal sau (yêu cầu quyền root):

```bash
# 1. Nạp một module vào Kernel
sudo insmod my_driver.ko

# 2. Liệt kê tất cả các module đang chạy trong hệ thống
lsmod

# 3. Gỡ bỏ một module ra khỏi hệ thống
sudo rmmod my_driver

# 4. Xem nhật ký (logs) của Kernel (rất hữu ích để xem lệnh printk của module in ra gì)
dmesg | tail -n 20
```



## 7. Thực hành 🛠: Build và Nạp Module "Hello Ring 0"

Để chạy đoạn code sau đây, bạn không thể dùng lệnh `gcc` thông thường vì nó cần liên kết với các thư viện lõi của Kernel. Bạn cần 3 bước sau:

### Bước 1: Cài đặt Kernel Headers
Máy tính của bạn cần bộ "từ điển" của Kernel để hiểu các hàm như `printk`, `module_init`.

```bash
# Cài đặt trên Ubuntu/Debian/Kali
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r)
```

### Bước 2: Tạo file mã nguồn và Makefile
Hãy tạo một thư mục mới, ví dụ `pwn_module`, và tạo 2 file bên trong:

**1. File `mymodule.c`:**
```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init my_init(void) {
    printk(KERN_INFO "PwnCollege: Module đã nạp thành công!\n");
    return 0;
}

static void __exit my_exit(void) {
    printk(KERN_INFO "PwnCollege: Tạm biệt Ring 0!\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
```

**2. File `Makefile`:** (Quan trọng: Đây là file điều khiển việc biên dịch)
*Lưu ý: Dấu thụt lùi ở lệnh `make` phải là một phím **TAB**, không phải dấu cách.*

```makefile
obj-m += mymodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

### Bước 3: Biên dịch và Chạy thử
Bây giờ, hãy mở terminal tại thư mục đó và chạy chuỗi lệnh sau:

```bash
# 1. Biên dịch module (sẽ tạo ra file mymodule.ko)
make

# 2. Nạp module vào Kernel (Ring 0)
sudo insmod mymodule.ko

# 3. Kiểm tra xem Kernel đã in dòng chữ "Hello" chưa
# Vì Kernel không có màn hình terminal, nó in vào một bộ đệm log riêng
dmesg | tail -n 5

# 4. Kiểm tra xem module có trong danh sách không
lsmod | grep mymodule

# 5. Gỡ module ra
sudo rmmod mymodule

# 6. Kiểm tra lại log để thấy lời chào tạm biệt
dmesg | tail -n 5
```

---

### Giải thích ý nghĩa các thành phần:

*   **`printk(KERN_INFO ...)`**: Tương tự `printf` nhưng dành cho Kernel. Vì Kernel có hàng nghìn thông báo mỗi giây, `KERN_INFO` giúp phân loại mức độ quan trọng của tin nhắn.
*   **`__init` và `__exit`**: Đây là các "macro" đánh dấu. `__init` báo cho Kernel biết hàm này chỉ dùng lúc nạp module, sau khi chạy xong có thể giải phóng bộ nhớ của chính hàm đó để tiết kiệm RAM.
*   **`MODULE_LICENSE("GPL")`**: Rất quan trọng. Nếu không có dòng này, Kernel sẽ coi module của bạn là "độc quyền" (proprietary), nó sẽ hiện cảnh báo "Tainted Kernel" và một số hàm bảo mật cao cấp sẽ bị khóa không cho module của bạn gọi tới.
