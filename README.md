# Emergency Preparedness Management System

A comprehensive web-based emergency preparedness and management system designed for schools and communities. This system enables real-time emergency alerts, drill management, incident reporting, and communication between students, parents, teachers, school administrators, and NDMA officials.

## Features

### Core Functionality
- **Multi-Role Authentication System**: Secure login for Students, Parents, Teachers, School Admins, and NDMA officials
- **Real-Time Emergency Alerts**: NDMA and admin-posted alerts with severity levels and location tracking
- **Emergency Drill Management**: Schedule, participate in, and track emergency drills with point rewards
- **Incident Reporting**: Comprehensive reporting system with file attachments and status tracking
- **Internal Messaging**: Communication system between different user roles
- **Dashboard Analytics**: Role-based dashboards with statistics and recent activity
- **Point-Based Gamification**: Reward system to encourage active participation

### Advanced Features
- **Role-Based Access Control**: Different permissions and UI elements based on user roles
- **File Upload Support**: Attach documents and images to reports and alerts
- **Real-Time Notifications**: Browser notifications for important updates
- **Mobile Responsive Design**: Optimized for desktop, tablet, and mobile devices
- **Activity Logging**: Comprehensive audit trail of all user actions
- **Auto-Refresh Data**: Automatic updates every 30 seconds for real-time information

## Technology Stack

### Backend
- **Node.js** with Express.js framework
- **MongoDB** with Mongoose ODM
- **JWT** for authentication
- **bcryptjs** for password hashing
- **Multer** for file uploads
- **Winston** for logging
- **Socket.io** for real-time communication (ready for implementation)

### Frontend
- **HTML5** with semantic markup
- **Tailwind CSS** for styling
- **Vanilla JavaScript** (ES6+) for interactivity
- **Font Awesome** for icons
- **Service Worker** for offline support (basic implementation)

### Security & Performance
- **Helmet.js** for security headers
- **Rate Limiting** to prevent abuse
- **CORS** configuration
- **Input Validation** with express-validator
- **Compression** for better performance
- **Environment Variables** for configuration

## Project Structure

```
emergency-preparedness-system/
├── server.js                 # Main server file
├── package.json              # Dependencies and scripts
├── .env.example             # Environment variables template
├── README.md                # This file
├── models/
│   └── index.js            # Database models (User, Alert, Drill, etc.)
├── scripts/
│   └── seed.js             # Database seeding script
├── public/                 # Static frontend files
│   ├── index.html          # Main HTML file
│   ├── js/
│   │   └── app.js          # Frontend JavaScript
│   ├── css/
│   │   └── custom.css      # Custom stylesheets
│   └── assets/             # Images, fonts, etc.
├── uploads/                # File uploads directory
├── logs/                   # Application logs
└── tests/                  # Test files (future implementation)
```

## Installation & Setup

### Prerequisites
- Node.js (v16.0.0 or higher)
- MongoDB (v4.4 or higher)
- npm (v8.0.0 or higher)

### Step-by-Step Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd emergency-preparedness-system
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Setup environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` file with your configuration:
   ```env
   NODE_ENV=development
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/emergency-prep
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   ```

4. **Create required directories**
   ```bash
   mkdir uploads logs
   ```

5. **Start MongoDB service**
   ```bash
   # On Windows
   net start MongoDB
   
   # On macOS (with brew)
   brew services start mongodb-community
   
   # On Linux
   sudo systemctl start mongod
   ```

6. **Seed the database with sample data**
   ```bash
   npm run seed
   ```

7. **Start the development server**
   ```bash
   npm run dev
   ```

8. **Access the application**
   Open your browser and navigate to: `http://localhost:3000`

## Test Credentials

After running the seed script, you can use these test accounts:

| Role | Email | Password | Description |
|------|-------|----------|-------------|
| NDMA | admin@ndma.gov.in | ndma123 | NDMA Administrator |
| School Admin | principal@school.edu | admin123 | School Principal |
| Teacher | sarah.teacher@school.edu | teacher123 | Teacher Account |
| Parent | john.parent@gmail.com | parent123 | Parent Account |
| Student | alex.student@school.edu | student123 | Student Account |

## User Roles & Permissions

### NDMA Officials
- Create and manage emergency alerts
- View all system reports and analytics
- Communicate with school administrators
- Monitor drill participation across institutions

### School Administrators
- Create emergency alerts for their institution
- Schedule and manage drills
- View all reports and user activity
- Manage teacher and student accounts
- Access comprehensive analytics dashboard

### Teachers
- Schedule emergency drills
- Report incidents and safety concerns
- Communicate with students and parents
- View drill participation and results
- Access teaching resources and guidelines

### Parents
- View emergency alerts and drill schedules
- Communicate with teachers and school administration
- Report concerns related to their children
- Track their children's drill participation
- Access safety resources and guidelines

### Students
- Participate in emergency drills
- View alerts and safety information
- Report safety concerns
- Communicate with teachers
- Earn points for active participation

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### Alerts
- `GET /api/alerts` - Get alerts (with pagination)
- `POST /api/alerts` - Create new alert (NDMA/Admin only)

### Drills
- `GET /api/drills` - Get scheduled drills
- `POST /api/drills` - Schedule new drill (Teacher/Admin/NDMA)
- `POST /api/drills/:id/join` - Join a drill

### Reports
- `GET /api/reports` - Get reports (role-filtered)
- `POST /api/reports` - Create new report

### Dashboard
- `GET /api/dashboard` - Get dashboard statistics

### Profile
- `GET /api/profile` - Get user profile
- `PUT /api/profile` - Update user profile

### Messages
- `GET /api/messages` - Get messages
- `POST /api/messages` - Send message

### Notifications
- `GET /api/notifications` - Get notifications
- `PUT /api/notifications/:id/read` - Mark notification as read

## Database Schema

### User Model
```javascript
{
  name: String,
  email: String (unique),
  password: String (hashed),
  role: Enum['student', 'parent', 'teacher', 'admin', 'ndma'],
  points: Number,
  drillsParticipated: [ObjectId],
  emergencyContact: Object,
  preferences: Object,
  isActive: Boolean
}
```

### Alert Model
```javascript
{
  title: String,
  description: String,
  type: Enum['critical', 'warning', 'info'],
  location: String,
  severity: Enum['low', 'medium', 'high', 'extreme'],
  category: Enum['weather', 'fire', 'security', 'health', 'infrastructure', 'other'],
  createdBy: ObjectId,
  isActive: Boolean,
  acknowledgments: Array
}
```

### Drill Model
```javascript
{
  title: String,
  type: Enum['fire', 'earthquake', 'lockdown', 'evacuation', 'flood', 'chemical-spill'],
  location: String,
  scheduledDate: Date,
  scheduledTime: String,
  participants: Array,
  status: Enum['scheduled', 'in-progress', 'completed', 'cancelled'],
  pointsAwarded: Number
}
```

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment (development/production) | development |
| `PORT` | Server port | 3000 |
| `MONGODB_URI` | MongoDB connection string | mongodb://localhost:27017/emergency-prep |
| `JWT_SECRET` | JWT signing secret | (required) |
| `JWT_EXPIRES_IN` | JWT expiration time | 24h |
| `BCRYPT_SALT_ROUNDS` | Password hashing rounds | 12 |
| `MAX_FILE_SIZE` | Maximum upload file size | 10485760 (10MB) |

### Rate Limiting
- API endpoints: 100 requests per 15 minutes
- Authentication endpoints: 5 requests per 15 minutes

## Development

### Available Scripts
- `npm start` - Start production server
- `npm run dev` - Start development server with nodemon
- `npm run seed` - Populate database with sample data
- `npm test` - Run tests (to be implemented)
- `npm run lint` - Run ESLint

### Development Guidelines
1. Follow RESTful API conventions
2. Use proper HTTP status codes
3. Implement proper error handling
4. Log important events and errors
5. Validate all input data
6. Use environment variables for configuration
7. Follow security best practices

## Security Features

### Authentication & Authorization
- JWT-based authentication
- Role-based access control
- Password hashing with bcrypt
- Session management

### Data Protection
- Input validation and sanitization
- XSS protection with Helmet.js
- Rate limiting to prevent abuse
- CORS configuration
- File upload restrictions

### Privacy
- User data encryption
- Secure password reset (to be implemented)
- Activity logging for audit trails
- GDPR compliance considerations

## Performance Optimization

### Backend
- Database indexing for better query performance
- Compression middleware for response compression
- Efficient pagination for large datasets
- Connection pooling for MongoDB

### Frontend
- Lazy loading of images and content
- Optimized bundle size
- Browser caching strategies
- Service worker for offline functionality

## Deployment

### Production Deployment

1. **Prepare environment**
   ```bash
   NODE_ENV=production
   PORT=3000
   MONGODB_URI=mongodb://your-mongodb-url
   JWT_SECRET=your-production-jwt-secret
   ```

2. **Install dependencies**
   ```bash
   npm ci --only=production
   ```

3. **Build and start**
   ```bash
   npm start
   ```

### Docker Deployment (Optional)
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

## Monitoring & Logging

### Log Files
- `logs/error.log` - Error logs
- `logs/combined.log` - All logs
- Console output for development

### Monitoring Endpoints
- Health check: `GET /health`
- System status: `GET /api/admin/stats` (Admin only)

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Ensure MongoDB is running
   - Check MongoDB URI in .env file
   - Verify network connectivity

2. **Authentication Errors**
   - Check JWT_SECRET in environment
   - Verify token expiration settings
   - Clear browser localStorage if needed

3. **File Upload Issues**
   - Check uploads directory permissions
   - Verify file size limits
   - Ensure allowed file types are correct

4. **Performance Issues**
   - Monitor database query performance
   - Check server resource usage
   - Optimize database indexes

## Future Enhancements

### Planned Features
- Real-time WebSocket notifications
- Mobile app development
- Advanced analytics dashboard
- Integration with external emergency services
- Multi-language support
- Advanced reporting and analytics
- Email and SMS notifications
- Push notifications
- Offline functionality
- Advanced user management
- Integration with school management systems

### Technical Improvements
- Automated testing suite
- CI/CD pipeline
- Docker containerization
- Load balancing
- Database clustering
- Advanced caching strategies
- Performance monitoring
- Security auditing tools

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Coding Standards
- Use ESLint configuration
- Follow JavaScript ES6+ standards
- Write meaningful commit messages
- Include tests for new features
- Update documentation as needed

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support & Contact

For support, bug reports, or feature requests:
- Create an issue in the repository
- Email: support@emergency-prep.system
- Documentation: https://docs.emergency-prep.system

## Acknowledgments

- NDMA (National Disaster Management Authority) for emergency management guidelines
- Open source community for various packages and tools used
- Contributors and testers who helped improve the system

---

**Built with ❤️ for safer communities**

*This system is designed to enhance emergency preparedness and response in educational institutions and communities. Regular drills, proper training, and community awareness remain the most important aspects of emergency preparedness.*
