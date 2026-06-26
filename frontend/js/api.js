/** URL gốc của backend API - tự động dùng hostname hiện tại */
const API_BASE = `${window.location.origin}/api`;

/** Lấy JWT token từ localStorage */
function getToken() {
    return localStorage.getItem("token");
}

/** Lấy thông tin người dùng từ localStorage */
function getUser() {
    const raw = localStorage.getItem("user");
    return raw ? JSON.parse(raw) : null;
}

/** Lưu token và thông tin người dùng vào localStorage sau khi đăng nhập */
function setAuth(token, user) {
    localStorage.setItem("token", token);
    localStorage.setItem("user", JSON.stringify(user));
}

/** Clear session and redirect to login */
function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    // Clear httpOnly cookie via backend (fire-and-forget)
    fetch("/api/auth/logout", {
        method: "POST",
        credentials: "include"
    }).catch(() => {});
    window.location.href = "/login.html";
}

/** Kiểm tra người dùng đã đăng nhập chưa */
function isLoggedIn() {
    return !!getToken();
}

/** Lấy vai trò đầu tiên của người dùng (citizen, officer) */
function getUserRole() {
    const user = getUser();
    return user?.roles?.[0] || null;
}

/**
 * Call API with automatic auth.
 * Sends httpOnly cookies automatically (credentials: "include").
 * Falls back to Authorization header for backward compatibility.
 * Auto-logout on 401 (expired token).
 */
async function apiFetch(path, options = {}) {
    const token = getToken();
    const headers = { ...options.headers };

    if (!(options.body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
    }

    // Send token in header for backward compatibility
    // (httpOnly cookie is sent automatically with credentials: "include")
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const url = path.startsWith("/api/") ? path : `${API_BASE}${path}`;
    const res = await fetch(url, {
        ...options,
        headers,
        credentials: "include" // Send cookies with every request
    });

    if (res.status === 401) {
        if (getToken()) {
            logout();
            return null;
        }
        // No token → on login/register page, let error surface normally
    }

    return res;
}

/** Gọi GET, trả về JSON */
async function apiGet(path) {
    const res = await apiFetch(path);
    if (!res) return null;
    if (!res.ok) throw new Error((await res.json()).message || "Request failed");
    return res.json();
}

/** Gọi POST với JSON body */
async function apiPost(path, body) {
    const res = await apiFetch(path, {
        method: "POST",
        body: JSON.stringify(body)
    });
    if (!res) return null;
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Request failed");
    return data;
}

/** Gọi POST với FormData (dùng cho upload file) */
async function apiPostForm(path, formData) {
    const res = await apiFetch(path, {
        method: "POST",
        body: formData
    });
    if (!res) return null;
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Request failed");
    return data;
}

/** Tải file dưới dạng blob, trả về URL tạm để hiển thị trong iframe */
async function apiBlobUrl(path) {
    const res = await apiFetch(path);
    if (!res) return null;
    if (!res.ok) {
        let message = "Request failed";
        try {
            message = (await res.json()).message || message;
        } catch {
            message = res.statusText || message;
        }
        throw new Error(message);
    }
    const blob = await res.blob();
    return URL.createObjectURL(blob);
}

/** Tải file về máy người dùng */
async function apiDownload(path, filename) {
    const blobUrl = await apiBlobUrl(path);
    if (!blobUrl) return;

    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = filename || "document.pdf";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

/** Yêu cầu đăng nhập, chuyển về login.html nếu chưa đăng nhập */
function requireAuth() {
    if (!isLoggedIn()) {
        window.location.href = "/login.html";
        return false;
    }
    return true;
}

/** Yêu cầu vai trò cụ thể, chuyển về trang chủ nếu không khớp */
function requireRole(...roles) {
    const user = getUser();
    if (!user || !roles.some(r => user.roles?.includes(r))) {
        window.location.href = "/";
        return false;
    }
    return true;
}
