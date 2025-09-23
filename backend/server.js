// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'emergency-system-secret-key-2025';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/emergency_system';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { 
        type: String, 
        required: true, 
        enum: ['student', 'parent', 'teacher', 'admin', 'ndma'] 
    },
    points: { type: Number, default: 0 },
    drillsParticipated: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Drill' }],
    createdAt: { type: Date, default: Date.now },
    lastActive: { type: Date, default: Date.now }
});

// Alert Schema
const alertSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    type: { 
        type: String, 
        required: true, 
        enum: ['critical', 'warning', 'info'] 
    },
    location: { type: String, required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    resolvedAt: { type: Date }
});

// Drill Schema
const drillSchema = new mongoose.Schema({
    type: { 
        type: String, 
        required: true, 
        enum: ['fire', 'earthquake', 'lockdown', 'evacuation'] 
    },
    location: { type: String, required: true },
    description: { type: String },
    scheduledDate: { type: Date, required: true },
    scheduledTime: { type: String, required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    status: { 
        type: String, 
        enum: ['scheduled', 'in-progress', 'completed', 'cancelled'],
        default: 'scheduled'
    },
    pointsAwarded: { type: Number, default: 10 },
    createdAt: { type: Date, default: Date.now },
    completedAt: { type: Date }
});

// Report Schema
const reportSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    type: { 
        type: String, 
        required: true, 
        enum: ['incident', 'drill-outcome', 'safety-concern', 'other'] 
    },
    location: { type: String },
    severity: { 
        type: String, 
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'medium'
    },
    reportedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { 
        type: String, 
        enum: ['pending', 'investigating', 'resolved', 'dismissed'],
        default: 'pending'
    },
    attachments: [{ type: String }],
    comments: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        comment: { type: String },
        timestamp: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now },
    resolvedAt: { type: Date }
});

// Message Schema
const messageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipients: [{ 
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        readAt: { type: Date }
    }],
    subject: { type: String, required: true },
    content: { type: String, required: true },
    type: { 
        type: String, 
        enum: ['general', 'emergency', 'drill-notification', 'alert-update'],
        default: 'general'
    },
    priority: { 
        type: String, 
        enum: ['low', 'medium', 'high', 'urgent'],
        default: 'medium'
    },
    attachments: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});

// Activity Log Schema
const activitySchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    action: { type: String, required: true },
    description: { type: String, required: true },
    entityType: { type: String }, // 'alert', 'drill', 'report', 'message'
    entityId: { type: mongoose.Schema.Types.ObjectId },
    metadata: { type: mongoose.Schema.Types.Mixed },
    timestamp: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const Alert = mongoose.model('Alert', alertSchema);
const Drill = mongoose.model('Drill', drillSchema);
const Report = mongoose.model('Report', reportSchema);
const Message = mongoose.model('Message', messageSchema);
const Activity = mongoose.model('Activity', activitySchema);

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Middleware for role-based authorization
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Authentication required' });
        }
        
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Insufficient permissions' });
        }
        
        next();
    };
};

// Utility function to log activity
const logActivity = async (userId, action, description, entityType = null, entityId = null, metadata = null) => {
    try {
        await Activity.create({
            user: userId,
            action,
            description,
            entityType,
            entityId,
            metadata
        });
    } catch (error) {
        console.error('Error logging activity:', error);
    }
};

// AUTHENTICATION ROUTES

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // Validate input
        if (!name || !email || !password || !role) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            role
        });

        await user.save();

        // Log activity
        await logActivity(user._id, 'USER_REGISTERED', `User ${name} registered with role ${role}`);

        res.status(201).json({ 
            message: 'User registered successfully',
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;

        // Find user
        const user = await User.findOne({ email, role });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Update last active
        user.lastActive = new Date();
        await user.save();

        // Generate token
        const token = jwt.sign(
            { 
                userId: user._id, 
                email: user.email, 
                role: user.role 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Log activity
        await logActivity(user._id, 'USER_LOGIN', `User logged in`);

        res.json({
            message: 'Login successful',
            token,
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                points: user.points
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// ALERT ROUTES

// Get alerts
app.get('/api/alerts', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const alerts = await Alert.find({ isActive: true })
            .populate('createdBy', 'name role')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Alert.countDocuments({ isActive: true });

        res.json({
            alerts,
            pagination: {
                total,
                page,
                pages: Math.ceil(total / limit),
                limit
            }
        });
    } catch (error) {
        console.error('Error fetching alerts:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create alert (NDMA and Admin only)
app.post('/api/alerts', authenticateToken, authorize('ndma', 'admin'), async (req, res) => {
    try {
        const { title, description, type, location } = req.body;

        if (!title || !description || !type || !location) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const alert = new Alert({
            title,
            description,
            type,
            location,
            createdBy: req.user.userId
        });

        await alert.save();
        await alert.populate('createdBy', 'name role');

        // Log activity
        await logActivity(
            req.user.userId, 
            'ALERT_CREATED', 
            `Created ${type} alert: ${title}`,
            'alert',
            alert._id,
            { type, location }
        );

        res.status(201).json({
            message: 'Alert created successfully',
            alert
        });
    } catch (error) {
        console.error('Error creating alert:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update alert
app.put('/api/alerts/:id', authenticateToken, authorize('ndma', 'admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;

        const alert = await Alert.findByIdAndUpdate(
            id,
            updates,
            { new: true }
        ).populate('createdBy', 'name role');

        if (!alert) {
            return res.status(404).json({ message: 'Alert not found' });
        }

        // Log activity
        await logActivity(
            req.user.userId,
            'ALERT_UPDATED',
            `Updated alert: ${alert.title}`,
            'alert',
            alert._id
        );

        res.json({
            message: 'Alert updated successfully',
            alert
        });
    } catch (error) {
        console.error('Error updating alert:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// DRILL ROUTES

// Get drills
app.get('/api/drills', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const drills = await Drill.find()
            .populate('createdBy', 'name role')
            .populate('participants', 'name role')
            .sort({ scheduledDate: 1 })
            .skip(skip)
            .limit(limit);

        const total = await Drill.countDocuments();

        res.json({
            drills,
            pagination: {
                total,
                page,
                pages: Math.ceil(total / limit),
                limit
            }
        });
    } catch (error) {
        console.error('Error fetching drills:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create drill (Teachers and Admins only)
app.post('/api/drills', authenticateToken, authorize('teacher', 'admin'), async (req, res) => {
    try {
        const { type, location, description, scheduledDate, scheduledTime } = req.body;

        if (!type || !location || !scheduledDate || !scheduledTime) {
            return res.status(400).json({ message: 'Required fields missing' });
        }

        const drill = new Drill({
            type,
            location,
            description,
            scheduledDate,
            scheduledTime,
            createdBy: req.user.userId
        });

        await drill.save();
        await drill.populate('createdBy', 'name role');

        // Log activity
        await logActivity(
            req.user.userId,
            'DRILL_CREATED',
            `Scheduled ${type} drill at ${location}`,
            'drill',
            drill._id,
            { type, location, scheduledDate, scheduledTime }
        );

        res.status(201).json({
            message: 'Drill scheduled successfully',
            drill
        });
    } catch (error) {
        console.error('Error creating drill:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Join drill
app.post('/api/drills/:id/join', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;

        const drill = await Drill.findById(id);
        if (!drill) {
            return res.status(404).json({ message: 'Drill not found' });
        }

        // Check if user already joined
        if (drill.participants.includes(userId)) {
            return res.status(400).json({ message: 'Already joined this drill' });
        }

        // Add user to participants
        drill.participants.push(userId);
        await drill.save();

        // Award points to user
        const user = await User.findById(userId);
        user.points += drill.pointsAwarded;
        user.drillsParticipated.push(drill._id);
        await user.save();

        // Log activity
        await logActivity(
            userId,
            'DRILL_JOINED',
            `Joined ${drill.type} drill at ${drill.location}`,
            'drill',
            drill._id,
            { pointsEarned: drill.pointsAwarded }
        );

        res.json({
            message: 'Successfully joined drill',
            pointsEarned: drill.pointsAwarded
        });
    } catch (error) {
        console.error('Error joining drill:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update drill status
app.put('/api/drills/:id/status', authenticateToken, authorize('teacher', 'admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        const drill = await Drill.findByIdAndUpdate(
            id,
            { 
                status,
                ...(status === 'completed' && { completedAt: new Date() })
            },
            { new: true }
        ).populate('createdBy', 'name role');

        if (!drill) {
            return res.status(404).json({ message: 'Drill not found' });
        }

        // Log activity
        await logActivity(
            req.user.userId,
            'DRILL_STATUS_UPDATED',
            `Updated drill status to ${status}`,
            'drill',
            drill._id,
            { status }
        );

        res.json({
            message: 'Drill status updated successfully',
            drill
        });
    } catch (error) {
        console.error('Error updating drill status:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// REPORT ROUTES

// Get reports
app.get('/api/reports', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        let query = {};
        
        // Role-based filtering
        if (!['admin', 'ndma'].includes(req.user.role)) {
            query.reportedBy = req.user.userId;
        }

        const reports = await Report.find(query)
            .populate('reportedBy', 'name role')
            .populate('assignedTo', 'name role')
            .populate('comments.user', 'name role')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Report.countDocuments(query);

        res.json({
            reports,
            pagination: {
                total,
                page,
                pages: Math.ceil(total / limit),
                limit
            }
        });
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create report
app.post('/api/reports', authenticateToken, async (req, res) => {
    try {
        const { title, description, type, location, severity } = req.body;

        if (!title || !description || !type) {
            return res.status(400).json({ message: 'Required fields missing' });
        }

        const report = new Report({
            title,
            description,
            type,
            location,
            severity,
            reportedBy: req.user.userId
        });

        await report.save();
        await report.populate('reportedBy', 'name role');

        // Log activity
        await logActivity(
            req.user.userId,
            'REPORT_CREATED',
            `Created ${type} report: ${title}`,
            'report',
            report._id,
            { type, severity }
        );

        res.status(201).json({
            message: 'Report created successfully',
            report
        });
    } catch (error) {
        console.error('Error creating report:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update report status
app.put('/api/reports/:id/status', authenticateToken, authorize('admin', 'ndma', 'teacher'), async (req, res) => {
    try {
        const { id } = req.params;
        const { status, assignedTo } = req.body;

        const updateData = { 
            status,
            ...(status === 'resolved' && { resolvedAt: new Date() }),
            ...(assignedTo && { assignedTo })
        };

        const report = await Report.findByIdAndUpdate(
            id,
            updateData,
            { new: true }
        ).populate('reportedBy', 'name role')
         .populate('assignedTo', 'name role');

        if (!report) {
            return res.status(404).json({ message: 'Report not found' });
        }

        // Log activity
        await logActivity(
            req.user.userId,
            'REPORT_STATUS_UPDATED',
            `Updated report status to ${status}`,
            'report',
            report._id,
            { status, assignedTo }
        );

        res.json({
            message: 'Report status updated successfully',
            report
        });
    } catch (error) {
        console.error('Error updating report status:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Add comment to report
app.post('/api/reports/:id/comments', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { comment } = req.body;

        if (!comment) {
            return res.status(400).json({ message: 'Comment is required' });
        }

        const report = await Report.findById(id);
        if (!report) {
            return res.status(404).json({ message: 'Report not found' });
        }

        report.comments.push({
            user: req.user.userId,
            comment
        });

        await report.save();
        await report.populate('comments.user', 'name role');

        // Log activity
        await logActivity(
            req.user.userId,
            'REPORT_COMMENT_ADDED',
            `Added comment to report: ${report.title}`,
            'report',
            report._id
        );

        res.json({
            message: 'Comment added successfully',
            report
        });
    } catch (error) {
        console.error('Error adding comment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// MESSAGE ROUTES

// Get messages
app.get('/api/messages', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const messages = await Message.find({
            $or: [
                { sender: req.user.userId },
                { 'recipients.user': req.user.userId }
            ]
        })
        .populate('sender', 'name role')
        .populate('recipients.user', 'name role')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);

        const total = await Message.countDocuments({
            $or: [
                { sender: req.user.userId },
                { 'recipients.user': req.user.userId }
            ]
        });

        res.json({
            messages,
            pagination: {
                total,
                page,
                pages: Math.ceil(total / limit),
                limit
            }
        });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Send message
app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { recipients, subject, content, type, priority } = req.body;

        if (!recipients || !subject || !content) {
            return res.status(400).json({ message: 'Required fields missing' });
        }

        const message = new Message({
            sender: req.user.userId,
            recipients: recipients.map(recipientId => ({ user: recipientId })),
            subject,
            content,
            type,
            priority
        });

        await message.save();
        await message.populate('sender', 'name role');
        await message.populate('recipients.user', 'name role');

        // Log activity
        await logActivity(
            req.user.userId,
            'MESSAGE_SENT',
            `Sent message: ${subject}`,
            'message',
            message._id,
            { recipientCount: recipients.length, type, priority }
        );

        res.status(201).json({
            message: 'Message sent successfully',
            messageData: message
        });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Mark message as read
app.put('/api/messages/:id/read', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const message = await Message.findById(id);
        if (!message) {
            return res.status(404).json({ message: 'Message not found' });
        }

        // Find the recipient and mark as read
        const recipient = message.recipients.find(r => r.user.toString() === req.user.userId);
        if (recipient && !recipient.readAt) {
            recipient.readAt = new Date();
            await message.save();
        }

        res.json({ message: 'Message marked as read' });
    } catch (error) {
        console.error('Error marking message as read:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// DASHBOARD ROUTES

// Get dashboard data
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Get user data
        const user = await User.findById(userId).populate('drillsParticipated');

        // Get active alerts count
        const activeAlerts = await Alert.countDocuments({ isActive: true });

        // Get unread messages count
        const unreadMessages = await Message.countDocuments({
            'recipients.user': userId,
            'recipients.readAt': { $exists: false }
        });

        // Get recent activity
        const recentActivity = await Activity.find({ user: userId })
            .sort({ timestamp: -1 })
            .limit(10);

        // Get upcoming drills
        const upcomingDrills = await Drill.find({
            scheduledDate: { $gte: new Date() },
            status: 'scheduled'
        }).limit(5);

        res.json({
            points: user.points,
            drillsParticipated: user.drillsParticipated.length,
            activeAlerts,
            unreadMessages,
            recentActivity: recentActivity.map(activity => ({
                description: activity.description,
                timestamp: activity.timestamp
            })),
            upcomingDrills: upcomingDrills.map(drill => ({
                type: drill.type,
                location: drill.location,
                scheduledDate: drill.scheduledDate,
                scheduledTime: drill.scheduledTime
            }))
        });
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// USER MANAGEMENT ROUTES (Admin only)

// Get all users
app.get('/api/users', authenticateToken, authorize('admin', 'ndma'), async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;
        const role = req.query.role;

        let query = {};
        if (role) {
            query.role = role;
        }

        const users = await User.find(query)
            .select('-password')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await User.countDocuments(query);

        res.json({
            users,
            pagination: {
                total,
                page,
                pages: Math.ceil(total / limit),
                limit
            }
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update user role (Admin only)
app.put('/api/users/:id/role', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;

        if (!['student', 'parent', 'teacher', 'admin', 'ndma'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role' });
        }

        const user = await User.findByIdAndUpdate(
            id,
            { role },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Log activity
        await logActivity(
            req.user.userId,
            'USER_ROLE_UPDATED',
            `Updated user role to ${role} for ${user.name}`,
            'user',
            user._id,
            { newRole: role }
        );

        res.json({
            message: 'User role updated successfully',
            user
        });
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// STATISTICS ROUTES (Admin and NDMA only)

// Get system statistics
app.get('/api/statistics', authenticateToken, authorize('admin', 'ndma'), async (req, res) => {
    try {
        // User statistics
        const totalUsers = await User.countDocuments();
        const usersByRole = await User.aggregate([
            { $group: { _id: '$role', count: { $sum: 1 } } }
        ]);

        // Alert statistics
        const totalAlerts = await Alert.countDocuments();
        const activeAlerts = await Alert.countDocuments({ isActive: true });
        const alertsByType = await Alert.aggregate([
            { $group: { _id: '$type', count: { $sum: 1 } } }
        ]);

        // Drill statistics
        const totalDrills = await Drill.countDocuments();
        const completedDrills = await Drill.countDocuments({ status: 'completed' });
        const drillsByType = await Drill.aggregate([
            { $group: { _id: '$type', count: { $sum: 1 } } }
        ]);

        // Report statistics
        const totalReports = await Report.countDocuments();
        const pendingReports = await Report.countDocuments({ status: 'pending' });
        const reportsByType = await Report.aggregate([
            { $group: { _id: '$type', count: { $sum: 1 } } }
        ]);

        // Recent activity
        const recentActivity = await Activity.find()
            .populate('user', 'name role')
            .sort({ timestamp: -1 })
            .limit(20);

        res.json({
            users: {
                total: totalUsers,
                byRole: usersByRole.reduce((acc, item) => {
                    acc[item._id] = item.count;
                    return acc;
                }, {})
            },
            alerts: {
                total: totalAlerts,
                active: activeAlerts,
                byType: alertsByType.reduce((acc, item) => {
                    acc[item._id] = item.count;
                    return acc;
                }, {})
            },
            drills: {
                total: totalDrills,
                completed: completedDrills,
                byType: drillsByType.reduce((acc, item) => {
                    acc[item._id] = item.count;
                    return acc;
                }, {})
            },
            reports: {
                total: totalReports,
                pending: pendingReports,
                byType: reportsByType.reduce((acc, item) => {
                    acc[item._id] = item.count;
                    return acc;
                }, {})
            },
            recentActivity: recentActivity.map(activity => ({
                user: activity.user.name,
                userRole: activity.user.role,
                action: activity.action,
                description: activity.description,
                timestamp: activity.timestamp
            }))
        });
    } catch (error) {
        console.error('Error fetching statistics:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Serve static files (frontend)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access the application at http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\nShutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

module.exports = app;