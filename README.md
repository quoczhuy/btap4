# Bộ 8 Test Case Kiểm thử Hệ thống

1. **[Test Public] (Endpoint Công Khai)** 
   - **Action:** Gọi `GET /health` không có Header Authorization. 
   - **Expect:** `200 OK`.
2. **[Test CORS] (Bẫy 2 - Preflight)**
   - **Action:** Trình duyệt gửi `OPTIONS /admin/exams` không kèm Token. 
   - **Expect:** `200 OK`, không bị bắt lỗi 401 nhờ `CORSMiddleware`.
3. **[Test Token 1] (Sai Token/Giả mạo)** 
   - **Action:** Gửi Token sai chữ ký vào `GET /exams`. 
   - **Expect:** `401 Unauthorized`.
4. **[Test Token 2] (Hết hạn)** 
   - **Action:** Gửi Token đã hết thời gian sử dụng vào `GET /exams`. 
   - **Expect:** `401 Unauthorized` (Token has expired).
5. **[Test Role 1] (Sai quyền Admin)** 
   - **Action:** Đăng nhập `student01` lấy Token, gọi `POST /admin/exams`. 
   - **Expect:** `403 Forbidden` (Bị chặn bởi router dependency).
6. **[Test Role 2] (Vượt Bẫy 3 - Quên Dependency)** 
   - **Action:** Đăng nhập `student01` gọi endpoint mới `DELETE /admin/exams/10` (Hàm không khai báo explicit Dependency).
   - **Expect:** `403 Forbidden` (Được APIRouter bảo vệ tự động).
7. **[Test Data Ownership 1] (Chính chủ)**
   - **Action:** Đăng nhập `student01`, gọi `GET /users/student01/results`. 
   - **Expect:** `200 OK` (Trả về đúng danh sách điểm).
8. **[Test Data Ownership 2] (Bẫy 4 - Đổi ID URL)**
   - **Action:** Đăng nhập `student01`, sửa URL thành `GET /users/student02/results`. 
   - **Expect:** `403 Forbidden` (Không được phép xem kết quả của người khác).