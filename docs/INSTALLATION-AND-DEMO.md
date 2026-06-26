# Cài đặt và hướng dẫn demo

## 1. Môi trường

- Windows 10/11.
- Node.js 20 trở lên.
- npm.
- OpenSSL 3.
- SoftHSM2.
- OpenSC.
- PKCS#11 provider cho OpenSSL.

Kiểm tra:

```powershell
node --version
npm --version
openssl version
softhsm2-util --version
pkcs11-tool --version
```

## 2. Thiết lập tự động

Tại thư mục gốc:

```powershell
npm.cmd run setup
```

Script sẽ:

- Kiểm tra môi trường.
- Tạo `backend/.env` từ `.env.example` với secret ngẫu nhiên.
- Cài dependencies.
- Khởi tạo JSON storage.
- Tạo Test Root CA, TSA, OCSP và archive seal.
- Tạo tài khoản demo.
- Cấp chứng thư phần mềm.
- Provision SoftHSM/PKCS#11 nếu công cụ có sẵn.

Bỏ qua token phần cứng:

```powershell
powershell -NoProfile `
    -ExecutionPolicy Bypass `
    -File ".\scripts\setup-demo.ps1" `
    -SkipHardwareTokens
```

## 3. Khởi động

```powershell
npm.cmd start
```

Giữ PowerShell mở.

```text
Portal:          http://localhost:3000
TSP:             http://127.0.0.1:3400
Client Agent:    http://127.0.0.1:3500
Archive Service: http://127.0.0.1:3600
```

Kiểm tra health:

```powershell
Invoke-WebRequest "http://localhost:3000" -UseBasicParsing |
    Select-Object StatusCode

Invoke-RestMethod "http://127.0.0.1:3400/health" |
    ConvertTo-Json -Depth 20

Invoke-RestMethod "http://127.0.0.1:3500/health" |
    ConvertTo-Json -Depth 20

Invoke-RestMethod "http://127.0.0.1:3600/health" |
    ConvertTo-Json -Depth 20
```

## 4. Tài khoản demo

```text
Citizen: citizen@test.com / citizen123
Officer: officer@test.com / officer123
Admin:   admin@test.com   / admin123
```

## 5. Kịch bản demo thuyết trình

### Công dân

1. Đăng nhập Citizen.
2. Tạo hồ sơ và upload PDF.
3. Chọn chứng thư PKCS#11.
4. Ký bằng Client Agent.
5. Chỉ ra khóa không xuất được và hồ sơ chuyển `submitted`.

### Cán bộ

1. Đăng nhập Officer.
2. Mở hồ sơ.
3. Kiểm tra chữ ký công dân.
4. Chọn ký từ xa.
5. Nhập OTP demo.
6. TSP dùng SoftHSM để ký.
7. PDF PAdES-LT được phát hành.

### Xác minh

Trình bày:

```text
CMS signature: valid
RFC 3161 timestamp: valid
DSS: present
VRI: valid
Embedded certificates: present
Embedded OCSP: present
Embedded CRL: present
PAdES level: PAdES-LT
```

### Quản trị chứng thư

1. Citizen gửi yêu cầu cấp chứng thư.
2. Admin duyệt và cấp.
3. Admin chủ động thu hồi một chứng thư test.
4. Kiểm tra Registry, CRL và OCSP chuyển `revoked`.
5. Thử ký lại và nhận lỗi từ chối.

### Tấn công

Có thể demo replay request, thay digest, sai owner, replay OTP, xóa DSS/VRI hoặc dùng chứng thư revoked.

```powershell
npm.cmd run test:attacks
```

## 6. Tạo tài khoản

### Admin

```powershell
npm.cmd run account:create-admin -- `
    --admin-id ADMIN-002 `
    --name "Quan tri vien 2" `
    --email "admin2@test.com" `
    --password "Admin2@123"
```

### Officer

```powershell
npm.cmd run account:create-officer -- `
    --officer-id OFFICER-002 `
    --name "Nguyen Van An" `
    --email "officer2@test.com" `
    --password "Officer2@123"
```

### Quản lý trạng thái

```powershell
npm.cmd run account:list
npm.cmd run account:disable -- --email "officer2@test.com"
npm.cmd run account:enable -- --email "officer2@test.com"
```

## 7. Reset demo

Dừng service trước khi reset:

```powershell
npm.cmd run reset:demo
```

Không tự xóa token database hoặc PKI nếu vẫn muốn giữ bộ khóa demo hiện tại.

## 8. Lỗi thường gặp

### Missing script

```powershell
npm.cmd run
```

### Cổng bị chiếm

```powershell
Get-NetTCPConnection -State Listen |
    Where-Object LocalPort -in 3000,3400,3500,3600
```

### Token không được tìm thấy

```powershell
$env:SOFTHSM2_CONF
softhsm2-util --show-slots
```

### Client Agent chưa ready

```powershell
Invoke-RestMethod "http://127.0.0.1:3500/health" |
    ConvertTo-Json -Depth 30
```

### Rate limit đăng nhập

HTTP 429 nghĩa là quá nhiều lần xác thực thất bại trong một cửa sổ thời gian. Chờ hết thời gian hoặc restart backend trong môi trường demo.

### Test local dùng nhầm SoftHSM

```powershell
$env:SIGNING_PROVIDER = "file"
$env:SOFTHSM_RUNTIME_PROBE = "false"
```

### E2E remote

```powershell
$env:SIGNING_PROVIDER = "softhsm"
$env:SOFTHSM_RUNTIME_PROBE = "true"
```
