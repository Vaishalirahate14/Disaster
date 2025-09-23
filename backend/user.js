// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    role: { type: String, enum: ['student', 'parent', 'teacher', 'admin', 'ndma'] },
    points: Number,
    drillsParticipated: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Drill' }],
    createdAt: { type: Date, default: Date.now },
    lastActive: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
