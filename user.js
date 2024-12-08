// user.js

const express = require("express");
const bcrypt = require("bcrypt");
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
    const { name, username, password, role } = req.body;

    // Validasi
    if (!name || !username || !password || !role) {
        return res.status(400).json({
            status: "error",
            message: "Semua data wajib diisi!"
        });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mengenkripsi password."
            });
        }

        const query = "INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)";
        db.query(query, [name, username, hashedPassword, role], (err, results) => {
            if (err) {
                console.log(err);
                return res.status(500).json({
                    status: "error",
                    message: "Gagal menambahkan pengguna."
                });
            }

            return res.status(200).json({
                status: "success",
                message: "Pengguna berhasil ditambahkan",
                data: {
                    id: results.insertId,
                    name,
                    username,
                    role
                }
            });
        });
    });
});

router.put("/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { name, username, password, role } = req.body;

    // Validation
    if (!name || !username || !password || !role) {
        return res.status(400).json({
            status: "error",
            message: "Semua data wajib diisi!"
        });
    }

    const updateData = { name, username, role };
    let query = "UPDATE users SET name = ?, username = ?, role = ? WHERE id = ?";
    let values = [name, username, role, id];

    if (password) {
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({
                    status: "error",
                    message: "Gagal mengenkripsi password."
                });
            }

            updateData.password = hashedPassword;
            query = "UPDATE users SET name = ?, username = ?, password = ?, role = ? WHERE id = ?";
            values = [name, username, hashedPassword, role, id];

            db.query(query, values, (err, results) => {
                if (err) {
                    return res.status(500).json({
                        status: "error",
                        message: "Gagal mengubah data pengguna."
                    });
                }

                return res.status(200).json({
                    status: "success",
                    message: "Pengguna berhasil diubah",
                    data: {
                        id,
                        name,
                        username,
                        role
                    }
                });
            });
        });
    } else {
        db.query(query, values, (err, results) => {
            if (err) {
                return res.status(500).json({
                    status: "error",
                    message: "Gagal mengubah data pengguna."
                });
            }

            return res.status(200).json({
                status: "success",
                message: "Pengguna berhasil diubah",
                data: {
                    id,
                    name,
                    username,
                    role
                }
            });
        });
    }
});

router.get("/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const query = "SELECT id, name, username, role FROM users WHERE id = ?";
    db.query(query, [id], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mengambil data pengguna."
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Pengguna tidak ditemukan."
            });
        }

        return res.status(200).json({
            status: "success",
            data: results[0]
        });
    });
});

router.delete("/:id", verifyToken, (req, res) => {
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

module.exports = router;
