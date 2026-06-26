# Kiểm thử và kết quả

## 1. Phạm vi

Bộ kiểm thử bao phủ authentication, authorization, Citizen signing, Client Agent software/PKCS#11, remote signing, OTP, TSP, SoftHSM, CMS/CAdES, RFC 3161, PAdES-LT, CRL/OCSP, archive, certificate lifecycle và Admin direct revocation.

## 2. Kiểm tra tĩnh

```powershell
npm.cmd run quality:static
```

Kiểm tra cú pháp JavaScript và tính hợp lệ của JSON.

## 3. Automated tests

```powershell
npm.cmd test
```

Bản final đã xác nhận:

```text
20 test files
113 tests
PASS
```

## 4. Attack scenarios

```powershell
npm.cmd run test:attacks
```

Attack 01–54 bao phủ token, authentication, PDF/CMS tampering, certificate binding, CRL/OCSP, TSA, replay, Client Agent, TSP, SoftHSM, Citizen signing, OTP, PAdES-LT và certificate administration.

`PASS` nghĩa là hệ thống phát hiện hoặc từ chối tấn công.

## 5. Local E2E

```powershell
npm.cmd run test:e2e:local
```

Bao gồm Citizen software signing, local officer signing, CMS/CAdES, RFC 3161, PAdES-LT, DSS/VRI và certificate lifecycle.

## 6. Hardware-backed E2E

```powershell
npm.cmd run test:e2e:hardware
```

Bao gồm Citizen PKCS#11, Officer remote SoftHSM, OTP, non-exportable key và remote PAdES-LT.

## 7. Kiểm tra tổng hợp

```powershell
npm.cmd run verify:system
```

Không chạy hardware:

```powershell
powershell -NoProfile `
    -ExecutionPolicy Bypass `
    -File ".\scripts\verify-system.ps1" `
    -SkipHardware
```

Kết quả mong đợi:

```text
SYSTEM CHECK: PASS
```

## 8. Benchmark

```powershell
npm.cmd run benchmark
```

Đo Citizen software/PKCS#11 signing, Officer local/remote signing, PAdES-LT verification, OCSP và archive creation.

Output:

```text
results/benchmark-signing.csv
results/benchmark-signing-summary.json
```

Các trường chính: operation, provider, runs, mean, median, min, max, p95, input/output size và result.

## 9. Evidence

E2E tạo output trong `evidence/`:

```text
citizen-software-e2e/
citizen-pkcs11-e2e/
pades-lt-local/
pades-lt-remote/
remote-otp-e2e/
softhsm-e2e/
```

Ý nghĩa file:

- `input.pdf`: tài liệu ban đầu.
- `signed-pades-bt.pdf`: revision đã ký và timestamp.
- `signed-pades-lt.pdf`: PDF cuối với DSS/VRI.
- `.cms.der`: CMS SignedData.
- `.tsq`: RFC 3161 request.
- `.tsr`: RFC 3161 response.
- `result.json`: báo cáo E2E.

Evidence là output sinh tự động và không cần commit lên GitHub.

## 10. Kết quả đã xác nhận

```text
JavaScript syntax: PASS
JSON validation: PASS
Automated tests: 20/20 files, 113 tests PASS
Attack scenarios: 01–54 PASS
Citizen software E2E: PASS
Citizen PKCS#11 E2E: PASS trên Windows
Local PAdES-LT: PASS
Remote SoftHSM signing: PASS trên Windows
OTP: PASS
RFC 3161: PASS
CRL/OCSP: PASS
Certificate lifecycle: PASS
Admin direct revocation: PASS
Service health checks: PASS
```

## 11. Tiêu chí PAdES-LT PASS

```text
CMS signature valid
Timestamp valid
Certificate chain valid
DSS present
VRI present
VRI binding valid
Embedded certificates present
Embedded OCSP valid
Embedded CRL valid
Incremental update valid
Offline verification ready
```

Reason code thành công: `VALID_PADES_LT`.

## 12. Diễn giải một số kết quả

- HTTP 409 khi replay: request/nonce đã dùng bị từ chối.
- `CERTIFICATE_OWNER_MISMATCH`: không thể dùng chứng thư sai chủ sở hữu.
- `OTP_REPLAY_DETECTED`: OTP/authorization không thể tái sử dụng.
- `PADES_DSS_MISSING`: verifier phát hiện DSS bị xóa.
- `CERTIFICATE_REVOKED`: chứng thư revoked không thể ký mới.

## 13. Giới hạn đánh giá

Kết quả chỉ phản ánh PoC: SoftHSM không tương đương HSM certified; chưa đánh giá side-channel vật lý, tải production, pháp lý chính thức, user study lớn, PAdES-LTA hoặc CA thương mại/quốc gia.
