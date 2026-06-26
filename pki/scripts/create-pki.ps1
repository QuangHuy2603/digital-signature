Write-Host "multi-officer PKI khong con cap mot chung thu officer dung chung." -ForegroundColor Yellow
Write-Host "Root CA hien co duoc giu nguyen." -ForegroundColor Cyan
Write-Host "Tao tai khoan can bo:" -ForegroundColor Cyan
Write-Host '  npm.cmd run account:create-officer -- --officer-id OFFICER-002 --name "Tran Thi Binh" --email officer2@test.com --password "Officer2@123"'
Write-Host "Cap chung thu rieng:" -ForegroundColor Cyan
Write-Host '  npm.cmd run pki:issue-officer -- --officer-id OFFICER-002'
Write-Host "Chi tao lai Root CA khi thuc su can:" -ForegroundColor Cyan
Write-Host '  powershell -ExecutionPolicy Bypass -File .\pki\scripts\initialize-root-ca.ps1 -Force'
