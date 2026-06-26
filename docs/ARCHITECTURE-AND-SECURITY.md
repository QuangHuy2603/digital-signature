# Kiến trúc và thiết kế bảo mật

## 1. Mục tiêu

Hệ thống hướng tới tính xác thực, toàn vẹn, chống replay, bảo vệ khóa riêng, quản lý thu hồi, chứng minh thời điểm ký, xác minh dài hạn và khả năng truy vết thao tác quản trị.

## 2. Thành phần

### Web Portal

Giao diện cho Citizen, Officer và Admin; tạo hồ sơ, xử lý hồ sơ, quản lý chứng thư và xác minh chữ ký.

### Portal API

Điều phối xác thực, phân quyền, digest SHA-256, signing request, nonce, TTL, kiểm tra chứng thư, PAdES-LT, TSP, TSA và Archive Service.

### Client Agent

Chạy trên localhost và hỗ trợ hai provider:

- `software`: khóa file dùng trong lab.
- `pkcs11`: khóa trong SoftHSM hoặc token tương thích.

Client Agent kiểm tra owner, role, digest, expiry, nonce, token label, key label và key ID.

### Remote Signing Service

```text
Portal
→ OTP authorization
→ TSP
→ OpenSSL PKCS#11 provider
→ SoftHSM
→ CMS/CAdES
→ RFC 3161 TSA
```

Khóa riêng không được xuất khỏi SoftHSM.

### PKI

Gồm Root CA, signer certificate, TSA certificate, OCSP responder, CRL, OCSP status và Certificate Registry.

### PAdES-LT Verifier

Kiểm tra PDF ByteRange, CMS, CAdES signing-certificate attribute, timestamp, certificate chain, trạng thái thu hồi, DSS, VRI, embedded certificate/OCSP/CRL và incremental update.

### Archive Service

Lưu PDF PAdES-LT, manifest, digest, verification result, timestamp và audit metadata. Archive là lớp bảo vệ bổ sung; bằng chứng chính nằm trong PDF.

## 3. Luồng công dân ký hồ sơ

```text
Citizen upload PDF
→ Portal tính SHA-256
→ tạo signing request
→ Client Agent ký bằng software hoặc PKCS#11
→ Portal xác minh ECDSA, X.509, CRL và OCSP
→ kiểm tra owner, role, nonce và expiry
→ hồ sơ chuyển sang submitted
```

Request chỉ sử dụng một lần và ràng buộc với citizen, document, certificate, digest, nonce và thời hạn.

## 4. Luồng cán bộ ký cục bộ

```text
Officer chọn ký local
→ Portal tạo request
→ Client Agent kiểm tra
→ software key ký CMS
→ TSA cấp timestamp
→ tạo PAdES-B-T
→ bổ sung DSS/VRI
→ tạo PAdES-LT
→ verifier kiểm tra
→ archive lưu kết quả
```

## 5. Luồng cán bộ ký từ xa

```text
Officer chọn ký remote
→ Portal phát OTP
→ Officer nhập OTP
→ Portal xác minh OTP
→ cấp authorization token ngắn hạn
→ TSP nhận request
→ SoftHSM ký qua PKCS#11
→ TSA cấp timestamp
→ tạo PAdES-B-T
→ bổ sung DSS/VRI
→ tạo PAdES-LT
→ verifier kiểm tra
→ archive lưu kết quả
```

OTP ràng buộc với officer, document, digest, signing request, certificate và nonce; chỉ dùng một lần và không lưu dạng rõ.

## 6. PAdES-LT

Revision đầu chứa CMS SignedData, ECDSA signature, signing-certificate attribute và RFC 3161 timestamp.

Incremental update thêm:

```text
/DSS
├── /Certs
├── /OCSPs
├── /CRLs
└── /VRI
```

VRI liên kết bằng chứng với chữ ký CMS cụ thể. Hệ thống không tuyên bố PAdES-LTA vì chưa có archive timestamp định kỳ.

## 7. Vòng đời chứng thư

### Cấp mới

```text
User gửi yêu cầu
→ PENDING
→ Admin duyệt
→ APPROVED
→ tạo khóa và CSR
→ CA cấp chứng thư
→ ISSUED
```

### Gia hạn

Gia hạn tạo khóa mới, CSR mới và version mới; chứng thư cũ chuyển `superseded`.

### Thu hồi theo yêu cầu

User gửi revoke request, Admin duyệt và thu hồi; Registry, CRL, OCSP và Client Agent được cập nhật.

### Admin chủ động thu hồi

Admin chọn chứng thư active, chọn lý do, nhập lại certificate ID và xác nhận. Hệ thống tạo lifecycle record và audit event.

Trạng thái chính:

```text
active
superseded
revoked
expired
```

Chứng thư không bị xóa vì còn cần cho việc xác minh tài liệu cũ.

## 8. CRL và OCSP

Khi thu hồi:

```text
Certificate Registry → revoked
CRL → thêm serial
OCSP → trả revoked
Client Agent/TSP → từ chối ký mới
```

Verifier phân biệt thời điểm thu hồi với thời điểm ký. Tài liệu ký hợp lệ trước khi thu hồi vẫn có thể xác minh nếu timestamp và bằng chứng PAdES-LT hợp lệ.

## 9. Mô hình lưu trữ

Dữ liệu được lưu trong:

```text
backend/storage/
client-agent/storage/
tsp-service/storage/
archive-service/storage/
```

Các file JSON quan trọng sử dụng atomic write. Thư mục rỗng trong Git được giữ bằng `.gitkeep` và tự được tạo lại khi setup.

## 10. Mô hình đe dọa và biện pháp

### Sửa tài liệu

- SHA-256.
- PDF ByteRange.
- CMS signature.
- DSS/VRI binding.
- Incremental update validation.

### Replay

- Nonce.
- TTL.
- One-time request.
- HMAC authentication.
- One-time OTP authorization.

### Sai chủ sở hữu

- Owner binding.
- Role binding.
- Certificate ID binding.
- PKCS#11 token/key binding.
- Fail-closed khi metadata thiếu.

### Lộ khóa

- PKCS#11.
- SoftHSM.
- Non-exportable key.
- OTP cho ký từ xa.
- Audit và revocation.

### CA/TSA/OCSP compromise

- Chứng thư riêng theo chức năng.
- Chain verification.
- Signature verification cho TSA/OCSP.
- Nhúng CRL/OCSP vào PAdES-LT.
- Kiểm tra thời điểm bằng chứng.

### Brute force

- Bcrypt.
- Rate limiting cho login/register.
- Không tính đăng nhập thành công vào giới hạn lỗi.
- JWT có thời hạn.
- Khóa tài khoản bằng Admin CLI.

## 11. Mục tiêu bảo mật

| Mục tiêu | Cơ chế |
|---|---|
| Authentication | Tài khoản, JWT, OTP |
| Integrity | SHA-256, CMS, PAdES |
| Replay protection | Nonce, TTL, one-time request |
| Key protection | PKCS#11, SoftHSM |
| Revocation | CRL, OCSP |
| Long-term validation | PAdES-LT, DSS, VRI |
| Accountability | Audit log |
| Least privilege | Citizen, Officer, Admin |

## 12. Giới hạn và hướng phát triển

Giới hạn: Test CA, SoftHSM, Admin gộp RA/CA, chưa có mobile secure enclave, PAdES-LTA, Keycloak production, threshold signature hoặc HSM certified.

Hướng phát triển: HSM FIPS 140-3, eID federation, mobile signing, dual control, PAdES-LTA, immutable audit, HA OCSP/TSA và MPC/threshold signing.
