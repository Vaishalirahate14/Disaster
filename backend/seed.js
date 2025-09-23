// scripts/seed.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/emergency_system';

// Import models (you need separate files for each model, e.g., models/User.js)
const User = require('../models/User');
const Alert = require('../models/Alert');
const Drill = require('../models/Drill');
const Report = require('../models/Report');
const Message = require('../models/Message');
const Activity = require('../models/Activity');

async function seedDatabase() {
    try {
        // Connect to MongoDB
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Connected to MongoDB');

        // Clear existing data
        await User.deleteMany({});
        await Alert.deleteMany({});
        await Drill.deleteMany({});
        await Report.deleteMany({});
        await Message.deleteMany({});
        await Activity.deleteMany({});
        console.log('Cleared existing data');

        // Create sample users
        const hashedPassword = await bcrypt.hash('password123', 12);

        const users = await User.create([
            { name: 'NDMA Administrator', email: 'admin@ndma.gov.in', password: hashedPassword, role: 'ndma', points: 0 },
            { name: 'School Principal', email: 'principal@school.edu', password: hashedPassword, role: 'admin', points: 0 },
            { name: 'Emergency Coordinator', email: 'coordinator@school.edu', password: hashedPassword, role: 'teacher', points: 0 },
            { name: 'Physics Teacher', email: 'teacher@school.edu', password: hashedPassword, role: 'teacher', points: 0 },
            { name: 'John Doe', email: 'john.student@school.edu', password: hashedPassword, role: 'student', points: 50 },
            { name: 'Jane Smith', email: 'jane.student@school.edu', password: hashedPassword, role: 'student', points: 75 },
            { name: 'Parent One', email: 'parent1@email.com', password: hashedPassword, role: 'parent', points: 0 },
            { name: 'Parent Two', email: 'parent2@email.com', password: hashedPassword, role: 'parent', points: 0 }
        ]);
        console.log('Created sample users');

        // Create sample alerts
        const alerts = await Alert.create([
            {
                title: 'Heavy Rainfall Alert',
                description: 'Heavy rainfall expected in the region. All outdoor activities should be cancelled.',
                type: 'warning',
                location: 'Delhi NCR',
                createdBy: users[0]._id,
                isActive: true
            },
            {
                title: 'School Safety Inspection',
                description: 'Routine safety inspection scheduled for all school buildings.',
                type: 'info',
                location: 'All School Buildings',
                createdBy: users[1]._id,
                isActive: true
            },
            {
                title: 'Fire Hazard Warning',
                description: 'Increased fire risk due to dry weather conditions. Extra precautions advised.',
                type: 'critical',
                location: 'Delhi Region',
                createdBy: users[0]._id,
                isActive: true
            }
        ]);
        console.log('Created sample alerts');

        // Create sample drills
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);

        const nextWeek = new Date();
        nextWeek.setDate(nextWeek.getDate() + 7);

        const drills = await Drill.create([
            {
                type: 'fire',
                location: 'Main Building',
                description: 'Regular fire drill for all students and staff in the main building.',
                scheduledDate: tomorrow,
                scheduledTime: '10:00',
                createdBy: users[2]._id,
                participants: [users[4]._id, users[5]._id],
                status: 'scheduled',
                pointsAwarded: 10
            },
            {
                type: 'earthquake',
                location: 'School Campus',
                description: 'Earthquake preparedness drill for all staff and students.',
                scheduledDate: nextWeek,
                scheduledTime: '11:00',
                createdBy: users[2]._id,
                participants: [users[4]._id, users[5]._id],
                status: 'scheduled',
                pointsAwarded: 15
            }
        ]);
        console.log('Created sample drills');

        // Create sample reports
        const reports = await Report.create([
            {
                title: 'Broken Window Report',
                description: 'A window in the main building was broken during the last drill.',
                type: 'safety-concern',
                location: 'Main Building',
                severity: 'medium',
                reportedBy: users[2]._id,
                status: 'pending'
            },
            {
                title: 'Fire Drill Outcome',
                description: 'Fire drill completed successfully with no incidents.',
                type: 'drill-outcome',
                location: 'Main Building',
                severity: 'low',
                reportedBy: users[2]._id,
                status: 'resolved'
            }
        ]);
        console.log('Created sample reports');

        // Create sample messages
        const messages = await Message.create([
            {
                sender: users[2]._id,
                recipients: [{ user: users[4]._id }, { user: users[5]._id }],
                subject: 'Upcoming Fire Drill',
                content: 'Please be ready for the fire drill tomorrow at 10:00 AM.',
                type: 'drill-notification',
                priority: 'high'
            },
            {
                sender: users[0]._id,
                recipients: [{ user: users[1]._id }],
                subject: 'NDMA Alert Update',
                content: 'Heavy rainfall warning has been issued for Delhi NCR.',
                type: 'alert-update',
                priority: 'urgent'
            }
        ]);
        console.log('Created sample messages');

        // Create sample activity logs
        const activities = await Activity.create([
            {
                user: users[0]._id,
                action: 'ALERT_CREATED',
                description: 'Created heavy rainfall warning alert',
                entityType: 'alert',
                entityId: alerts[0]._id
            },
            {
                user: users[2]._id,
                action: 'DRILL_SCHEDULED',
                description: 'Scheduled fire drill for main building',
                entityType: 'drill',
                entityId: drills[0]._id
            }
        ]);
        console.log('Created sample activity logs');

        console.log('Database seeding completed successfully!');
        process.exit(0);

    } catch (error) {
        console.error('Error seeding database:', error);
        process.exit(1);
    }
}

seedDatabase();
