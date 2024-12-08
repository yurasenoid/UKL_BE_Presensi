const express = require("express");
const mysql = require("mysql2");
const { verifyToken } = require("./auth");

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306
});

const router = express.Router();

router.post("/", verifyToken, (req, res) => {
    const { userId, checkInTime, checkOutTime } = req.body;

    // Validation
    if (!userId || !checkInTime) {
        return res.status(400).json({
            status: "error",
            message: "User ID dan waktu masuk harus diisi!"
        });
    }

    const query = "INSERT INTO attendance (user_id, check_in_time, check_out_time) VALUES (?, ?, ?)";
    db.query(query, [userId, checkInTime, checkOutTime || null], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mencatat absensi."
            });
        }

        return res.status(200).json({
            status: "success",
            message: "Absensi berhasil dicatat",
            data: {
                id: results.insertId,
                userId,
                checkInTime,
                checkOutTime
            }
        });
    });
});

module.exports = router;
