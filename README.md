# Digital Signature Capstone

Nền tảng chữ ký số **PAdES-LT** cho Cổng Dịch vụ Hành chính Công, xây dựng cho đồ án môn **NT219 – Mật mã học**.

Hệ thống mô phỏng toàn bộ chu trình ký điện tử: công dân ký hồ sơ, cán bộ ký phát hành, ký cục bộ qua Client Agent, ký từ xa qua TSP + OTP + SoftHSM, timestamp RFC 3161, kiểm tra CRL/OCSP, nhúng DSS/VRI vào PDF và quản lý vòng đời chứng thư.

> Đây là PoC phục vụ học tập. Test CA, SoftHSM và tài khoản demo không được sử dụng trong production.

## Tính năng chính

### Citizen

- Đăng ký, đăng nhập và tạo hồ sơ.
- Tải PDF và ký qua Client Agent.
- Chọn provider `software` hoặc `pkcs11`.
- Theo dõi trạng thái xử lý.
- Gửi yêu cầu cấp, gia hạn hoặc thu hồi chứng thư.

### Officer

- Tiếp nhận hồ sơ đã được công dân ký.
- Kiểm tra chữ ký công dân.
- Ký cục bộ bằng Client Agent.
- Ký từ xa qua TSP, OTP và SoftHSM.
- Phát hành PDF PAdES-LT.

### Admin

- Phê duyệt, từ chối, cấp và gia hạn chứng thư.
- Thu hồi theo yêu cầu hoặc chủ động thu hồi trực tiếp.
- Theo dõi Certificate Registry, CRL, OCSP và audit log.
- Quản lý tài khoản Officer/Admin bằng CLI.

## Vai trò

| Role | Chức năng |
|---|---|
| `citizen` | Tạo hồ sơ, ký hồ sơ, quản lý chứng thư cá nhân |
| `officer` | Xử lý hồ sơ và ký phát hành |
| `admin` | Quản trị tài khoản, chứng thư, CRL và OCSP |

Trong phạm vi PoC, `admin` gộp chức năng RA và CA Admin. Hệ thống production nên tách hai nhiệm vụ này.

## Kiến trúc tổng quan

```text
Citizen / Officer / Admin
            |
            v
       Web Portal
            |
            v
       Portal API
       /    |     \
      /     |      \
Client    Remote    Certificate
Agent     Signing   Administration
  |          |            |
  |          v            v
  |      TSP Service     PKI
  |          |       CA / CRL / OCSP / TSA
  v          v
Software   SoftHSM
PKCS#11    PKCS#11
      \       /
       \     /
       PAdES-LT
           |
           v
    Verification and Archive
```

Các service mặc định:

| Thành phần | Địa chỉ |
|---|---|
| Portal API và giao diện | `http://localhost:3000` |
| TSP Service | `http://127.0.0.1:3400` |
| Client Agent | `http://127.0.0.1:3500` |
| Archive Service | `http://127.0.0.1:3600` |

## Chuẩn và thuật toán

- ECDSA P-256.
- SHA-256.
- X.509.
- CMS/PKCS#7 và thuộc tính CAdES.
- RFC 3161 timestamp.
- PAdES-B-T làm revision chữ ký ban đầu.
- PAdES-LT làm định dạng PDF cuối.
- DSS và VRI.
- CRL và OCSP.
- PKCS#11 và SoftHSM.
- HMAC-SHA256 cho request nội bộ và OTP.
- JWT cho phiên đăng nhập.
- Bcrypt cho mật khẩu.

## Lưu trữ

Dự án không sử dụng SQL, ORM hoặc NoSQL server. Dữ liệu runtime được lưu trong JSON và các thư mục `storage/`, với thao tác ghi file nguyên tử cho dữ liệu quan trọng.

## Cấu trúc repository

```text
digital-signature-capstone/
├── backend/
├── frontend/
├── client-agent/
├── tsp-service/
├── archive-service/
├── pki/
├── infrastructure/
├── scripts/
├── evidence/
├── results/
├── docs/
├── package.json
├── README.md
├── LICENSE
├── .gitignore
└── .env.example
```

## Yêu cầu môi trường

- Windows 10/11.
- Node.js 20 trở lên.
- npm.
- OpenSSL 3 có provider.
- SoftHSM2.
- OpenSC và `pkcs11-tool`.
- PKCS#11 provider cho OpenSSL.

## Cài đặt nhanh

```powershell
npm.cmd run setup
npm.cmd start
```

Hoặc chỉ cài dependencies:

```powershell
npm.cmd --prefix ".\backend" ci
```

Sau khi chạy `npm.cmd start`, truy cập:

```text
http://localhost:3000
```

## Tài khoản demo

```text
Citizen: citizen@test.com / citizen123
Officer: officer@test.com / officer123
Admin:   admin@test.com   / admin123
```

Các tài khoản được tạo bởi `npm.cmd run setup`.

## Quản lý tài khoản bằng CLI

### Tạo Admin

```powershell
npm.cmd run account:create-admin -- `
    --admin-id ADMIN-002 `
    --name "Quan tri vien 2" `
    --email "admin2@test.com" `
    --password "Admin2@123"
```

### Tạo Officer

```powershell
npm.cmd run account:create-officer -- `
    --officer-id OFFICER-002 `
    --name "Nguyen Van An" `
    --email "officer2@test.com" `
    --password "Officer2@123"
```

### Liệt kê, khóa và kích hoạt

```powershell
npm.cmd run account:list
npm.cmd run account:disable -- --email "officer2@test.com"
npm.cmd run account:enable -- --email "officer2@test.com"
```

Officer mới phải được Admin cấp chứng thư trước khi ký.

## Kiểm thử

```powershell
npm.cmd run quality:static
npm.cmd test
npm.cmd run test:attacks
npm.cmd run test:e2e:local
npm.cmd run test:e2e:hardware
npm.cmd run benchmark
npm.cmd run verify:system
```

Không chạy hardware E2E:

```powershell
powershell -NoProfile `
    -ExecutionPolicy Bypass `
    -File ".\scripts\verify-system.ps1" `
    -SkipHardware
```

## Tài liệu

- [Kiến trúc và bảo mật](docs/ARCHITECTURE-AND-SECURITY.md)
- [Cài đặt và demo](docs/INSTALLATION-AND-DEMO.md)
- [Kiểm thử và kết quả](docs/TESTING-AND-RESULTS.md)

## Giới hạn

- Test CA, không phải CA được pháp luật công nhận.
- SoftHSM chỉ mô phỏng HSM/USB Token.
- Provider software chỉ dùng cho lab.
- Admin tích hợp RA và CA.
- Chưa có mobile signing thật.
- Chưa có PAdES-LTA.
- Chưa có Keycloak production hoặc eID federation.
- Không dùng trực tiếp trong production.

## GitHub và bảo mật

Không commit `.env`, private key, token database, PIN, secret, dữ liệu hồ sơ, OTP, nonce, signing job, log, audit runtime hoặc `node_modules`.

```powershell
git init
git add .
git status
```

Không sử dụng `git add -f` để ép các file bí mật vào repository.

## License

MIT License. Chỉ phục vụ học tập, nghiên cứu và trình diễn kỹ thuật.
