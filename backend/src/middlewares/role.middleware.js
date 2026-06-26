/**
 * role.middleware.js - Phân quyền dựa trên vai trò người dùng.
 * Kiểm tra req.user.roles có chứa ít nhất một vai trò yêu cầu.
 */

/** Trả 403 nếu người dùng không có vai trò yêu cầu */
export const requireRole = (...roles) => (req, res, next) => {
    const userRoles = req.user?.roles || [];
    const hasRole = roles.some(r => userRoles.includes(r));
    if (!hasRole) {
        return res.status(403).json({
            message: `Requires one of: ${roles.join(", ")}`
        });
    }
    next();
};
