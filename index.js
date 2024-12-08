require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 8000;

//Middleware
app.use(bodyParser.json());

//Connect Database
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});



//JWT Middleware
function verifyToken(req, res, next) {
    const token = req.header("Authorization");
    if (!token) {
        return res.status(403).json({
            status: "error",
            message: "Token tidak ditemukan, akses ditolak!",
        });
    }

    const tokenWithoutBearer = token.split(" ")[1];
    jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({
                status: "error",
                message: "Token tidak valid!",
            });
        }

        req.user = decoded;
        next();
    });
}


function isKaryawan(req, res, next) {
    if (req.user.role !== 'karyawan') {
        return res.status(403).json({
            status: "error",
            message: "Akses ditolak! Hanya karyawan yang dapat mengakses rute ini.",
        });
    }
    next();
}

//Auth
app.post("/api/auth/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            status: "error",
            message: "Username dan password wajib diisi!"
        });
    }

    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({
                status: "error",
                message: "Username atau password salah!"
            });
        }

        const user = results[0];

        if (user.role !== "karyawan") {
            return res.status(403).json({
                status: "error",
                message: "Hanya karyawan yang dapat login."
            });
        }

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) {
                return res.status(401).json({
                    status: "error",
                    message: "Username atau password salah!"
                });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: "2h" }
            );

            return res.status(200).json({
                status: "success",
                message: "Login berhasil",
                token: token
            });
        });
    });
});


// Create Data
app.post("/api/users", verifyToken, (req, res) => {
    const { name, username, sandi, role } = req.body;

    if (!name || !username || !sandi || !role) {
        return res.status(400).json({
            status: "error",
            message: "Semua data wajib diisi!"
        });
    }

    const checkQuery = "SELECT id FROM users WHERE username = ?";
    db.query(checkQuery, [username], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({
                status: "error",
                message: "Gagal memeriksa username."
            });
        }

        if (results.length > 0) {
            return res.status(400).json({
                status: "error",
                message: "Username sudah digunakan. Gunakan username lain."
            });
        }

    bcrypt.hash(sandi, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({
                status: 'error',
                message: 'Failed to hash password.'
            });
        }

        const query = 'INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)';
        db.query(query, [name, username, hashedPassword, role], (err, results) => {
            if (err) {
                console.error('Error inserting user:', err);
                return res.status(500).json({
                    status: 'error',
                    message: 'Failed to add user to the database.'
                });
            }

            const newUser = {
                id: results.insertId,
                name,
                username,
                role
            };

            return res.status(200).json({
                status: "success",
                message: "Pengguna berhasil ditambahkan",
                data: newUser
            });
        });
    });
});


//Update Data
app.put("/api/users/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { name, username, sandi, role } = req.body;

    if (!name || !username || !sandi || !role) {
        return res.status(400).json({
            status: "error",
            message: "Semua data wajib diisi!"
        });
    }

    const checkQuery = "SELECT id FROM users WHERE username = ?";
    db.query(checkQuery, [username], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({
                status: "error",
                message: "Gagal memeriksa username."
            });
        }

        if (results.length > 0) {
            return res.status(400).json({
                status: "error",
                message: "Username sudah digunakan. Gunakan username lain."
            });
        }

    bcrypt.hash(sandi, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({
                status: 'error',
                message: 'Failed to hash password.'
            });
        }

        const query = 'UPDATE users SET name = ?, username = ?, password = ?, role = ? WHERE id = ?';
        db.query(query, [name, username, hashedPassword, role, id], (err, results) => {
            if (err) {
                console.error('Error updating user:', err);
                return res.status(500).json({
                    status: 'error',
                    message: 'Failed to update user in the database.'
                });
            }

            const updatedUser = {
                id,
                name,
                username,
                role
            };

            return res.status(200).json({
                status: "success",
                message: "Pengguna berhasil diubah",
                data: updatedUser
            });
        });
    });
});


//Get Data by ID
app.get("/api/users/:id", verifyToken, (req, res) => {
    const { id } = req.params; 
    const query = "SELECT id, name, username, role FROM users WHERE id = ?";

    db.query(query, [id], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mengambil data pengguna."
            });
        }

        if (!results || results.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Pengguna tidak ditemukan."
            });
        }

        const user = results[0];
        return res.status(200).json({
            status: "success",
            data: {
                id: user.id,
                name: user.name,
                username: user.username,
                role: user.role
            }
        });
    });
});

// Get All Users
app.get("/api/users", verifyToken, (req, res) => {
    const query = "SELECT id, name, username, role FROM users";

    db.query(query, (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mengambil data pengguna."
            });
        }

        if (!results || results.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Tidak ada pengguna ditemukan."
            });
        }

        const users = results.map(user => ({
            id: user.id,
            name: user.name,
            username: user.username,
            role: user.role
        }));

        return res.status(200).json({
            status: "success",
            data: users
        });
    });
});

//Delete Data
app.delete("/api/users/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const query = "DELETE FROM users WHERE id = ?";

    db.query(query, [id], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal menghapus pengguna."
            });
        }

        return res.status(200).json({
            status: "success",
            message: "Pengguna berhasil dihapus"
        });
    });
});

//Presensi
app.post("/api/attendance", verifyToken, (req, res) => {
    const { user_id, date, time, status } = req.body;

    if (!user_id || !date || !time || !status) {
        return res.status(400).json({
            status: "error",
            message: "Semua data wajib diisi!"
        });
    }

    const validStatuses = ['hadir', 'izin', 'sakit', 'alpa'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({
            status: "error",
            message: "Status presensi tidak valid!"
        });
    }

    const query = "INSERT INTO attendance (user_id, date, time, status) VALUES (?, ?, ?, ?)";
    db.query(query, [user_id, date, time, status], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mencatat presensi."
            });
        }

        return res.status(200).json({
            status: "success",
            message: "Presensi berhasil dicatat",
            data: {
                attendance_id: results.insertId,
                user_id,
                date,
                time,
                status
            }
        });
    });
});

//Histori Presensi
app.get("/api/attendance/history/:user_id", verifyToken, (req, res) => {
    const { user_id } = req.params;

    const query = "SELECT attendance_id, date, time, status FROM attendance WHERE user_id = ? ORDER BY date DESC, time DESC";

    db.query(query, [user_id], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mengambil riwayat presensi."
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Riwayat presensi tidak ditemukan untuk pengguna ini."
            });
        }

        return res.status(200).json({
            status: "success",
            data: results.map(row => ({
                attendance_id: row.attendance_id,
                date: row.date,
                time: row.time,
                status: row.status
            }))
        });
    });
});

//Sum Presensi
app.get("/api/attendance/summary/:user_id", verifyToken, (req, res) => {
    const { user_id } = req.params;
    const { month } = req.query;

    const regex = /^(0[1-9]|1[0-2])-\d{4}$/;
    if (!month || !regex.test(month)) {
        return res.status(400).json({
            status: "error",
            message: "Format bulan tidak valid. Gunakan format MM-YYYY."
        });
    }

    const query = `
            SELECT status, COUNT(*) AS count
            FROM attendance
            WHERE user_id = ? AND DATE_FORMAT(date, '%m-%Y') = ?
            GROUP BY status
        `;

    db.query(query, [user_id, month], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mengambil rekap kehadiran."
            });
        }

        const attendanceSummary = {
            hadir: 0,
            izin: 0,
            sakit: 0,
            alpa: 0
        };

        results.forEach(row => {
            if (attendanceSummary[row.status] !== undefined) {
                attendanceSummary[row.status] = row.count;
            }
        });

        return res.status(200).json({
            status: "success",
            data: {
                user_id: user_id,
                month: month,
                attendance_summary: attendanceSummary
            }
        });
    });
});

//Analytic Presensi
app.post("/api/attendance/analysis", verifyToken, (req, res) => {
    const { start_date, end_date, group_by } = req.body;

    if (!start_date || !end_date) {
        return res.status(400).json({
            status: "error",
            message: "Parameter start_date dan end_date diperlukan.",
        });
    }

    if (!group_by || !["role"].includes(group_by)) {
        return res.status(400).json({
            status: "error",
            message: "Parameter group_by tidak valid. Gunakan 'kelas' atau 'jabatan'.",
        });
    }

    const query = `
        SELECT 
            users.${group_by} AS role,
            attendance.status AS status,
            COUNT(attendance.status) AS count
        FROM 
            attendance
        INNER JOIN 
            users 
        ON 
            attendance.user_id = users.id
        WHERE 
            attendance.date BETWEEN ? AND ?
        GROUP BY 
            users.${group_by}, attendance.status
    `;

    db.query(query, [start_date, end_date], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                status: "error",
                message: "Terjadi kesalahan pada server.",
            });
        }

        const groupedAnalysis = {};
        results.forEach((row) => {
            const group = row.group_name || "Unspecified";
            const status = row.status.toLowerCase();

            if (!groupedAnalysis[group]) {
                groupedAnalysis[group] = {
                    group,
                    total_users: 0,
                    attendance_rate: {
                        hadir_percentage: 0,
                        izin_percentage: 0,
                        sakit_percentage: 0,
                        alpa_percentage: 0,
                    },
                    total_attendance: {
                        hadir: 0,
                        izin: 0,
                        sakit: 0,
                        alpa: 0,
                    },
                };
            }

            groupedAnalysis[group].total_attendance[status] += row.count;
        });

        // Hitung persentase kehadiran
        Object.values(groupedAnalysis).forEach((group) => {
            const totalUser = Object.values(group.total_users)
            

            const total = Object.values(group.total_attendance).reduce((sum, val) => sum + val, 0);

            if (total > 0) {
                group.attendance_rate.hadir_percentage =
                    (group.total_attendance.hadir / total) * 100 || 0;
                group.attendance_rate.izin_percentage =
                    (group.total_attendance.izin / total) * 100 || 0;
                group.attendance_rate.sakit_percentage =
                    (group.total_attendance.sakit / total) * 100 || 0;
                group.attendance_rate.alpa_percentage =
                    (group.total_attendance.alpa / total) * 100 || 0;
            }
        });

        return res.status(200).json({
            status: "success",
            data: {
                analysis_period: {
                    start_date,
                    end_date,
                },
                grouped_analysis: Object.values(groupedAnalysis),
            },
        });
    });
});


const PORT = 8000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});