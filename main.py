# Phần A. Phân tích Input/Output
# Để hệ thống phân quyền chính xác, chúng ta cần xác định rõ các luồng dữ liệu sau:

# Dữ liệu có trong JWT (Payload):

# sub: Định danh người dùng (username).

# role: Vai trò của người dùng tại thời điểm cấp token.

# exp: Thời gian hết hạn của token.

# Dữ liệu cần lấy từ hệ thống (Database/Mock Data):

# Trạng thái hoạt động (is_active) để chặn tài khoản đã bị khóa.

# Quyền hạn gốc (role trong DB) để đối chiếu, tránh việc token bị giả mạo quyền.

# Thông tin request cần dùng để phân quyền:

# HTTP Method (GET, POST, PATCH...).

# URL Path & Path Parameters (VD: exam_id, user_id) để xác định đối tượng thao tác.

# Header Authorization chứa Bearer Token.

# Kết quả khi được phép truy cập:

# Trả về mã HTTP 200 OK hoặc 201 Created kèm dữ liệu nghiệp vụ dạng JSON.

# Kết quả khi token hoặc quyền không hợp lệ:

# 401 Unauthorized: Không có token, sai chữ ký, hoặc token hết hạn.

# 403 Forbidden: Token hợp lệ nhưng tài khoản bị khóa, hoặc không đủ quyền thao tác (Admin/User), hoặc vi phạm quyền sở hữu dữ liệu cá nhân.

# Phần B. Đề xuất giải pháp
# Giải pháp 1: Sử dụng Dependency tại từng endpoint
# Sử dụng cơ chế Depends() của FastAPI để tiêm (inject) logic kiểm tra quyền vào từng hàm xử lý (endpoint).

# Cơ chế: Khai báo current_user = Depends(require_admin) tại chữ ký hàm.

# Ưu điểm: Code dễ đọc, linh hoạt, dễ dàng truy cập trực tiếp vào các biến Path Parameter.

# Giải pháp 2: Sử dụng Authorization Middleware
# Viết một Middleware ở tầng thấp (@app.middleware("http")) để đánh chặn và kiểm tra mọi request trước khi vào Router.

# Cơ chế: Dùng Regex đối chiếu chuỗi URL (/admin/exams/10/lock) với một từ điển quyền hạn (PROTECTED_ROUTES).

# Ưu điểm: Quản lý tập trung tại một nơi, khó bị bỏ sót.

# Giải pháp 3: Phương án kết hợp (Router-level Dependency)
# Sử dụng Middleware chỉ để ghi log/CORS. Xác thực và phân quyền sẽ do Dependency đảm nhận, nhưng được gắn ở cấp độ APIRouter thay vì từng endpoint lẻ tẻ. Các kiểm tra sở hữu dữ liệu sẽ được thực hiện bên trong hàm.

# Cơ chế: Gom nhóm các endpoint của Admin vào admin_router và gắn dependencies=[Depends(require_admin)].

#Sourch code:
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, APIRouter, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError, ExpiredSignatureError

# --- CẤU HÌNH ---
SECRET_KEY = "exam-secret-key-system"
ALGORITHM = "HS256"
app = FastAPI(title="Online Exam RBAC API")

# BẪY 2: Xử lý CORS Preflight (OPTIONS)
# Đặt Middleware ở tầng cao nhất để xử lý OPTIONS trước khi vào logic Router
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- MOCK DATA ---
USERS = {
    "admin01": {"username": "admin01", "password": "123", "role": "admin", "is_active": True},
    "student01": {"username": "student01", "password": "123", "role": "user", "is_active": True},
    "student02": {"username": "student02", "password": "123", "role": "user", "is_active": True},
}

EXAMS = [{"id": 10, "name": "C++ Programming", "locked": False}]
RESULTS = {
    "student01": [{"exam_id": 10, "score": 9}],
    "student02": [{"exam_id": 10, "score": 7}],
}

# --- DEPENDENCIES (XÁC THỰC & PHÂN QUYỀN) ---
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token structure")
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid signature")

    user = USERS.get(username)
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=403, detail="User is inactive or not found")
    
    return user

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

# BẪY 3: Quên gắn dependency
# Giải pháp: Gắn Dependency phân quyền Admin ngay tại mức độ Router
admin_router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


# --- PUBLIC ENDPOINTS ---
@app.get("/health")
def health_check():
    return {"status": "UP"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = USERS.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Wrong credentials")
    
    expire = datetime.now(timezone.utc) + timedelta(minutes=60)
    token = jwt.encode(
        {"sub": user["username"], "role": user["role"], "exp": expire}, 
        SECRET_KEY, 
        algorithm=ALGORITHM
    )
    return {"access_token": token, "token_type": "bearer"}


# --- SHARED ENDPOINTS ---
@app.get("/exams")
def get_exams(current_user: dict = Depends(get_current_user)):
    return {"exams": EXAMS}

# BẪY 4: User thay đổi ID trên URL
@app.get("/users/{user_id}/results")
def get_user_results(user_id: str, current_user: dict = Depends(get_current_user)):
    # Phân quyền: Admin xem được tất cả, User chỉ xem được của chính mình
    if current_user["role"] != "admin" and current_user["username"] != user_id:
        raise HTTPException(status_code=403, detail="Cannot access other user's data")
    return {"results": RESULTS.get(user_id, [])}


# --- ADMIN ENDPOINTS (Được bảo vệ bởi Router) ---
@admin_router.post("/exams")
def create_exam():
    return {"message": "Exam created successfully"}

# BẪY 1: Đường dẫn có path parameter
@admin_router.patch("/exams/{exam_id}/lock")
def lock_exam(exam_id: int):
    return {"message": f"Exam {exam_id} locked"}

@admin_router.get("/results")
def get_all_results():
    return {"results": RESULTS}

@admin_router.delete("/exams/{exam_id}")
def delete_exam(exam_id: int):
    # API này mô phỏng lỗi lập trình viên quên gắn quyền. 
    # Nhưng do dùng APIRouter, nó vẫn được bảo vệ tuyệt đối.
    return {"message": f"Exam {exam_id} deleted"}

# Nhúng router vào ứng dụng chính
app.include_router(admin_router)

# #Phần C
# # +----------------------------------+----------------------+----------------------+------------------------+
# # |             Tiêu chí             |      Dependency      |      Middleware      |   Phương án kết hợp    |
# # +----------------------------------+----------------------+----------------------+------------------------+
# # | Dễ đọc code                      |         Cao          |      Trung bình      |        Rất cao         |
# # | Khả năng tái sử dụng             |       Rất tốt        |         Tốt          |         Tối ưu         |
# # | Nguy cơ bỏ sót phân quyền        |         Cao          |         Thấp         |          Thấp          |
# # | Xử lý path parameter             |        Rất dễ        |       Rất khó        |         Rất dễ         |
# # | Xử lý CORS preflight             |         Tốt          |        Dễ lỗi        |          Tốt           |
# # | Kiểm tra quyền sở hữu dữ liệu    |       Rất tốt        |         Khó          |        Rất tốt         |
# # | Khả năng kiểm thử                |       Dễ dàng        |       Phức tạp       |        Dễ dàng         |
# # | Khả năng bảo trì                 |         Cao          |         Thấp         |        Rất cao         |
# # | Hiệu năng                        |         Cao          |       Thấp hơn       |          Cao           |
# # +----------------------------------+----------------------+----------------------+------------------------+