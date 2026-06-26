/**
 * auth.js - Xử lý đăng nhập, đăng ký và điều hướng thanh điều hướng.
 * Tự động gắn sự kiện cho form login/register nếu tồn tại trên trang.
 */
document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const registerForm = document.getElementById("registerForm");
    const errorEl = document.getElementById("authError");

    // Xử lý đăng nhập
    if (loginForm) {
        loginForm.addEventListener("submit", async (event) => {
            event.preventDefault();

            if (errorEl) {
                errorEl.textContent = "";
                errorEl.style.display = "none";
            }

            const email = loginForm.email.value.trim();
            const password = loginForm.password.value;

            try {
                const response = await apiPost("/auth/login", {
                    email,
                    password
                });

                setAuth(response.data.token, response.data.user);

                const roles = response.data.user.roles || [];
                const role = roles[0];

                if (role === "admin") {
                    window.location.href = "/admin/dashboard.html";
                } else if (role === "officer") {
                    window.location.href = "/officer/dashboard.html";
                } else {
                    window.location.href = "/citizen/dashboard.html";
                }
            } catch (error) {
                if (errorEl) {
                    errorEl.textContent =
                        error.message || "Đăng nhập thất bại. Vui lòng thử lại.";

                    errorEl.style.display = "block";
                }
            }
        });
    }

    // Xử lý đăng ký
    if (registerForm) {
        registerForm.addEventListener("submit", async (event) => {
            event.preventDefault();

            if (errorEl) {
                errorEl.textContent = "";
                errorEl.style.display = "none";
            }

            const fullName = registerForm.full_name.value.trim();
            const email = registerForm.email.value.trim();
            const password = registerForm.password.value;
            const confirmPassword =
                registerForm.confirm_password.value;

            if (password !== confirmPassword) {
                if (errorEl) {
                    errorEl.textContent =
                        "Mật khẩu xác nhận không khớp.";

                    errorEl.style.display = "block";
                }

                return;
            }

            try {
                await apiPost("/auth/register", {
                    full_name: fullName,
                    email,
                    password
                });

                window.location.href =
                    "/login.html?registered=1";
            } catch (error) {
                if (errorEl) {
                    errorEl.textContent =
                        error.message || "Đăng ký thất bại. Vui lòng thử lại.";

                    errorEl.style.display = "block";
                }
            }
        });
    }

    // Cập nhật thanh điều hướng khi trang tải xong
    updateNav();
});

/**
 * Cập nhật thanh điều hướng dựa trên trạng thái đăng nhập.
 */
function updateNav() {
    const navAuth = document.getElementById("navAuth");
    const navThutuc = document.getElementById("navThutuc");

    if (!navAuth) {
        return;
    }

    const user = getUser();

    if (user) {
        const roles = user.roles || [];
        const role = roles[0];

        const dashboardPath = role === "admin"
            ? "/admin/dashboard.html"
            : role === "officer"
                ? "/officer/dashboard.html"
                : "/citizen/dashboard.html";

        if (navThutuc) {
            navThutuc.href = dashboardPath;
        }

        navAuth.textContent = "";

        // Hiển thị tên người dùng
        const userSpan = document.createElement("span");
        userSpan.className = "nav-user";

        const displayName =
            user.full_name || user.email || "Người dùng";

        userSpan.textContent = `${displayName} (${role || "citizen"})`;

        // Nút vào trang quản lý
        const dashboardLink = document.createElement("a");
        dashboardLink.href = dashboardPath;
        dashboardLink.className = "btn btn-sm btn-outline";
        dashboardLink.textContent = "Trang quản lý";

        // Nút đăng xuất
        const logoutButton = document.createElement("button");
        logoutButton.type = "button";
        logoutButton.className = "btn btn-sm btn-danger";
        logoutButton.textContent = "Đăng xuất";

        logoutButton.addEventListener("click", () => {
            logout();
        });

        navAuth.appendChild(userSpan);
        navAuth.appendChild(dashboardLink);
        navAuth.appendChild(logoutButton);
    } else {
        navAuth.textContent = "";

        // Nút xác minh
        const verifyLink = document.createElement("a");
        verifyLink.href = "/verify.html";
        verifyLink.className = "btn btn-sm btn-verify";
        verifyLink.textContent = "Xác minh";

        // Nút đăng ký
        const registerLink = document.createElement("a");
        registerLink.href = "/register.html";
        registerLink.className = "btn btn-sm btn-outline";
        registerLink.textContent = "Đăng ký";

        // Nút đăng nhập
        const loginLink = document.createElement("a");
        loginLink.href = "/login.html";
        loginLink.className = "btn btn-sm btn-primary";
        loginLink.textContent = "Đăng nhập";

        navAuth.appendChild(verifyLink);
        navAuth.appendChild(registerLink);
        navAuth.appendChild(loginLink);
    }
}
