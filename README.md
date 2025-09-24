# Emergency Preparedness Management System

A comprehensive web-based emergency preparedness and management system designed for schools and communities. This system enables NDMA officials, school administrators, teachers, students, and parents to collaborate effectively in emergency preparedness, alert management, and drill coordination.

## 🚀 Features

### User Roles & Permissions
- **NDMA Officials**: Create and manage emergency alerts, monitor incidents
- **School Administrators**: Oversee all activities, manage users, access analytics
- **Teachers**: Conduct drills, report incidents, communicate with students/parents
- **Students**: Participate in drills, earn points, report issues
- **Parents**: Stay informed about alerts, communicate with school staff

### Core Functionality
- **Real-time Emergency Alerts**: Live emergency notifications with location-based filtering
- **Interactive Drill Management**: Schedule, participate in, and track emergency drills
- **Points-based Gamification**: Reward system for active participation
- **Incident Reporting**: Comprehensive reporting system with status tracking
- **Communication Hub**: Messaging system between all stakeholders
- **Analytics Dashboard**: Role-based dashboards with personalized insights
- **Mobile Responsive Design**: Optimized for all device types

## 🛠️ Technology Stack

### Frontend
- **HTML5 & CSS3**: Semantic markup and modern styling
- **Tailwind CSS**: Utility-first CSS framework for rapid UI development
- **JavaScript (ES6+)**: Modern JavaScript with async/await patterns
- **Font Awesome**: Comprehensive icon library
- **Responsive Design**: Mobile-first approach

### Backend
- **Node.js**: JavaScript runtime environment
- **Express.js**: Fast, unopinionated web framework
- **MongoDB**: NoSQL database for flexible data storage
- **Mongoose**: MongoDB object modeling library
- **JWT**: JSON Web Tokens for secure authentication
- **bcrypt**: Password hashing library

### Security Features
- Role-based access control (RBAC)
- JWT-based authentication
- Password hashing with bcrypt
- Input validation and sanitization
- CORS protection
- Rate limiting
- Helmet.js security headers

## 📋 Prerequisites

Before running this application, make sure you have the following installed:

- **Node.js** (v16.0.0 or higher)
- **npm** (v8.0.0 or higher)
- **MongoDB** (v5.0 or higher)
- **Git** (for version control)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-organization/emergency-preparedness-system.git
cd emergency-preparedness-system
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Environment Setup

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Update the `.env` file with your configuration:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/emergency_system

# JWT Secret (use a strong, random string in production)
JWT_SECRET=your-super-secret-jwt-key-here

# Email Configuration (optional)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
```

### 4. Database Setup

Start MongoDB service:

```bash
# On macOS with Homebrew
brew services start mongodb-community

# On Ubuntu/Debian
sudo systemctl start mongod

# On Windows
net start MongoDB
```

### 5. Seed the Database (Optional)

Populate the database with sample data:

```bash
npm run seed
```

This will create sample users with the following credentials:
- **NDMA Admin**: admin@ndma.gov.in / password123
- **School Principal**: principal@school.edu / password123
- **Teacher**: teacher@school.edu / password123
- **Student**: john.student@school.edu / password123
- **Parent**: parent1@email.com / password123

### 6. Start the Application

```bash
# Development mode with auto-restart
npm run dev

# Production mode
npm start
```

The application will be available at `http://localhost:3000`

## 📁 Project Structure

```
emergency-preparedness-system/
├── server.js                 # Main server file
├── package.json              # Dependencies and scripts
├── .env.example              # Environment variables template
├── README.md                 # Project documentation
├── models/
│   └── index.js              # Database models
├── scripts/
│   └── seed.js               # Database seeding script
├── public/                   # Static frontend files
│   ├── index.html            # Main HTML file
│   ├── css/                  # Custom stylesheets
│   ├── js/                   # Frontend JavaScript
│   └── assets/               # Images, fonts, etc.
├── logs/                     # Application logs
├── uploads/                  # File uploads directory
└── tests/                    # Test files
```

## 🔐 Authentication & Authorization

The system uses JWT-based authentication with role-based access control:

### User Roles
1. **NDMA** - Full alert management, system oversight
2. **Admin** - School-level administration, user management
3. **Teacher** - Drill coordination, incident reporting
4. **Student** - Drill participation, basic reporting
5. **Parent** - View alerts, communicate with school

### Protected Routes
- All API endpoints require authentication except registration and login
- Role-specific endpoints are protected with authorization middleware
- JWT tokens expire after 24 hours (configurable)

## 🌟 Key Features Explained

### 1. Emergency Alert System
- **Real-time Notifications**: Instant alerts for critical situations
- **Severity Levels**: Critical, Warning, and Informational alerts
- **Location-based**: Geographically relevant alerts
- **Multi-channel**: Web, email, and SMS notifications (configurable)

### 2. Drill Management
- **Scheduling**: Plan drills with date, time, and location
- **Participation Tracking**: Monitor who joins each drill
- **Points System**: Gamification to encourage participation
- **Performance Analytics**: Track drill effectiveness and participation rates

### 3. Incident Reporting
- **Comprehensive Forms**: Detailed incident documentation
- **Status Tracking**: From report to resolution
- **Assignment System**: Assign reports to appropriate personnel
- **Comment System**: Collaborative resolution process

### 4. Communication Hub
- **Multi-recipient Messaging**: Send messages to multiple users
- **Priority Levels**: Mark urgent communications
- **Read Receipts**: Track message delivery and reading
- **Threaded Conversations**: Organized communication chains

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `NODE_ENV` | Environment mode | development |
| `MONGODB_URI` | MongoDB connection string | mongodb://localhost:27017/emergency_system |
| `JWT_SECRET` | JWT signing secret | (required) |
| `BCRYPT_ROUNDS` | Password hashing rounds | 12 |
| `RATE_LIMIT_WINDOW` | Rate limiting window (minutes) | 15 |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window | 100 |

### Database Configuration

The system uses MongoDB with Mongoose ODM. Key collections:

- **users**: User accounts and profiles
- **alerts**: Emergency alerts and notifications
- **drills**: Scheduled and completed drills
- **reports**: Incident and safety reports
- **messages**: Internal communication
- **activities**: System activity logs
- **notifications**: User notifications

## 🚀 Deployment

### Production Deployment

1. **Environment Setup**:
   ```bash
   NODE_ENV=production
   JWT_SECRET=your-production-jwt-secret
   MONGODB_URI=your-production-mongodb-uri
   ```

2. **Build and Start**:
   ```bash
   npm install --production
   npm start
   ```
