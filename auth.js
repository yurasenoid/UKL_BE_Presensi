require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306
});

const router = express.Router();

router.post("/login", (req, res) => {
    const { username, password } = req.body;

    // Validasi input
    if (!username || !password) {
        return res.status(400).json({
            status: "error",
            message: "Username dan password wajib diisi!"
        });
    }

    // Cek apakah username ada di database
    const query = "SELECT id, name, username, password, role FROM users WHERE username = ?";
    db.query(query, [username], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal melakukan login."
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Username tidak ditemukan."
            });
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).json({
                    status: "error",
                    message: "Terjadi kesalahan saat memverifikasi password."
                });
            }

            if (!isMatch) {
                return res.status(401).json({
                    status: "error",
                    message: "Password salah."
                });
            }

            // Create JWT token
            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '3h' }
            );

            return res.status(200).json({
                status: "success",
                message: "Login berhasil",
                token: token
            });
        });
    });
});

function verifyToken(req, res, next) {
    const token = req.header("Authorization");

    if (!token) {
        return res.status(403).json({
            status: "error",
            message: "Token tidak ditemukan, akses ditolak!"
        });
    }

    const tokenWithoutBearer = token.split(" ")[1];

    jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({
                status: "error",
                message: "Token tidak valid!"
            });
        }

        req.user = decoded;

        if (req.user.role !== 'karyawan') {
            return res.status(403).json({
                status: "error",
                message: "Akses ditolak! Hanya karyawan yang dapat mengakses rute ini."
            });
        }

        next();
    });
}

module.exports = { router, verifyToken };
