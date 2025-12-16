# Healthcare Access Connector API

A production-ready healthcare access platform built with Go, connecting patients with healthcare providers, managing appointments, and facilitating seamless healthcare service delivery.

## 🏥 Features

### Core Capabilities
- 👥 **Patient & Provider Management** - Comprehensive user profiles with role-based access
- 📅 **Appointment Scheduling** - Smart booking system with availability management
- 🏥 **Provider Discovery** - Search and filter healthcare providers by specialty, location, availability
- 📧 **Automated Notifications** - Email alerts for appointments, reminders, cancellations
- 💳 **Insurance Integration** - Insurance verification and coverage checking (ready to implement)
- 📊 **Medical Records** - Secure storage and sharing of health records (HIPAA-ready architecture)

### Technical Features
- 🔐 **JWT Authentication** - Secure token-based authentication with role-based access (patient, provider, admin)
- 🚀 **High Performance** - Redis caching for optimized data access
- 📨 **Event-Driven** - NATS messaging for async operations (appointment reminders, notifications)
- 📊 **Observability** - Prometheus metrics, structured logging
- 🛡️ **Security** - Rate limiting, CORS, input validation, HIPAA-compliant design
- 🗃️ **Clean Architecture** - Separation of concerns, dependency injection
- 🐳 **Docker Ready** - Full Docker Compose setup
- ✅ **Production Ready** - Health checks, graceful shutdown, comprehensive error handling

## 🏗️ Architecture

```
cmd/api/              # Application entry point
internal/
├── app/              # Application initialization & DI
├── config/           # Configuration management
├── domain/           # Domain models (Patient, Provider, Appointment, etc.)
├── repository/       # Data access layer
├── service/          # Business logic layer
│   ├── patient/      # Patient management
│   ├── provider/     # Provider management
│   ├── appointment/  # Appointment scheduling
│   └── notification/ # Email & SMS notifications
├── handler/          # HTTP handlers
├── middleware/       # HTTP middleware (auth, logging, rate limiting)
├── cache/            # Caching abstraction (Redis)
├── messaging/        # Message broker (NATS)
├── email/            # Email service (SES/SMTP)
└── validator/        # Input validation
```

## 📋 Prerequisites

- Go 1.21+
- Docker & Docker Compose
- PostgreSQL 16
- Redis 7
- NATS 2
- sqlc (for code generation)
- golang-migrate (for migrations)
- AWS account (optional, for production email via SES)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/nyashahama/healthcare-access-connector-backend.git
cd healthcare-access-connector-backend
cp .env.example .env
```

### 2. Generate JWT Secret

```bash
make generate-jwt
# Copy output to .env JWT_SECRET
```

### 3. Start Services

```bash
# Start all services with Docker Compose
make docker-up

# View logs
make docker-logs

# Access Mailpit (local email UI)
open http://localhost:8025
```

### 4. Run Database Migrations

```bash
# Run migrations
make migrate-up DB_URL="postgres://postgres:admin@localhost:5432/healthcare_db?sslmode=disable"
```

### 5. Generate Database Code

```bash
make sqlc
```

### 6. Build and Run

```bash
# Build binary
make build

# Run application
make run

# Or use hot reload for development
make dev
```

## 📡 API Endpoints

### Public Endpoints

#### Patient Registration
```bash
POST /api/v1/patients/register
Content-Type: application/json

{
  "first_name": "John",
  "last_name": "Doe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "phone": "+1234567890",
  "date_of_birth": "1990-01-15",
  "gender": "male",
  "address": {
    "street": "123 Main St",
    "city": "Boston",
    "state": "MA",
    "zip_code": "02101",
    "country": "USA"
  }
}
```

#### Provider Registration
```bash
POST /api/v1/providers/register
Content-Type: application/json

{
  "first_name": "Jane",
  "last_name": "Smith",
  "email": "dr.smith@hospital.com",
  "password": "SecurePass123!",
  "phone": "+1234567890",
  "specialization": "Cardiology",
  "license_number": "MD123456",
  "hospital_affiliation": "General Hospital",
  "address": {
    "street": "456 Medical Center",
    "city": "Boston",
    "state": "MA",
    "zip_code": "02101"
  },
  "consultation_fee": 150.00
}
```

#### Login (Patient or Provider)
```bash
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "user_type": "patient"  # or "provider"
}
```

#### Search Providers
```bash
GET /api/v1/providers/search?specialization=cardiology&city=Boston&available_date=2025-01-20
```

### Protected Endpoints (Require Bearer Token)

#### Book Appointment (Patient)
```bash
POST /api/v1/appointments
Authorization: Bearer <token>
Content-Type: application/json

{
  "provider_id": "uuid-here",
  "appointment_date": "2025-01-20T10:00:00Z",
  "reason": "Regular checkup",
  "notes": "First visit"
}
```

#### Get My Appointments (Patient)
```bash
GET /api/v1/patients/me/appointments
Authorization: Bearer <token>
```

#### Get Provider Schedule (Provider)
```bash
GET /api/v1/providers/me/schedule?date=2025-01-20
Authorization: Bearer <token>
```

#### Update Appointment Status (Provider)
```bash
PATCH /api/v1/appointments/{id}/status
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "confirmed"  # pending, confirmed, completed, cancelled
}
```

#### Get Patient Profile
```bash
GET /api/v1/patients/me
Authorization: Bearer <token>
```

#### Update Provider Availability
```bash
POST /api/v1/providers/me/availability
Authorization: Bearer <token>
Content-Type: application/json

{
  "day_of_week": "monday",
  "start_time": "09:00",
  "end_time": "17:00",
  "slot_duration_minutes": 30
}
```

### Health & Monitoring

```bash
GET /health      # Comprehensive health check
GET /ready       # Readiness probe
GET /live        # Liveness probe
GET /metrics     # Prometheus metrics
```

## 📧 Email Notifications

The system automatically sends emails for:

1. **Welcome Emails** - Patient/Provider registration
2. **Appointment Confirmation** - When appointment is booked
3. **Appointment Reminder** - 24 hours before appointment
4. **Appointment Cancellation** - When cancelled by patient or provider
5. **Appointment Rescheduling** - When date/time changes
6. **Password Reset** - For account recovery

### Local Development (Mailpit)
- Web UI: http://localhost:8025
- All emails caught locally, no real sending

### Production (AWS SES)
See configuration section below for AWS SES setup.

## ⚙️ Configuration

All configuration via environment variables. Key options:

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_URL` | PostgreSQL connection | Required |
| `JWT_SECRET` | JWT signing secret (32+ chars) | Required |
| `JWT_EXPIRY_HOURS` | Token expiration | 24 |
| `PORT` | Server port | 8080 |
| `LOG_LEVEL` | Logging level | info |
| `ENVIRONMENT` | Environment | development |
| `REDIS_URL` | Redis connection | redis://localhost:6379 |
| `NATS_URL` | NATS connection | nats://localhost:4222 |
| `EMAIL_PROVIDER` | Email provider (ses/smtp) | smtp |
| `APPOINTMENT_REMINDER_HOURS` | Hours before appointment to send reminder | 24 |
| `MAX_APPOINTMENTS_PER_DAY` | Max appointments per provider per day | 10 |
| `PROVIDER_SEARCH_RADIUS_KM` | Search radius for nearby providers | 50 |

## 🗄️ Database Schema

### Core Tables

**patients**
- id, email, password_hash, first_name, last_name
- phone, date_of_birth, gender
- address (JSON), insurance_info (JSON)
- created_at, updated_at

**providers**
- id, email, password_hash, first_name, last_name
- specialization, license_number, years_of_experience
- hospital_affiliation, consultation_fee
- address (JSON), availability (JSON)
- rating, total_reviews
- created_at, updated_at

**appointments**
- id, patient_id, provider_id
- appointment_date, duration_minutes
- status (pending, confirmed, completed, cancelled)
- reason, notes, prescription (text)
- created_at, updated_at

**provider_schedules**
- id, provider_id
- day_of_week, start_time, end_time
- slot_duration_minutes, is_available
- created_at, updated_at

**reviews**
- id, patient_id, provider_id, appointment_id
- rating (1-5), comment
- created_at, updated_at

## 🛠️ Development

### Create Database Migration

```bash
make migrate-create name=create_patients_table
```

### Run Tests

```bash
# All tests with coverage
make test

# Integration tests
make test-integration

# Unit tests only
make test-unit
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Tidy dependencies
make tidy

# All checks
make check
```

## 🐳 Docker Commands

```bash
# Start all services
make docker-up

# View logs
make docker-logs

# Stop services
make docker-down

# Rebuild and restart
docker-compose up -d --build

# Shell into API container
make docker-shell
```

## 🚀 Production Deployment

### Environment Variables for Production

```bash
# Security
JWT_SECRET=<generate-with-make-generate-jwt>
ENVIRONMENT=production

# Database (use managed PostgreSQL)
DB_URL=postgres://user:pass@your-db-host:5432/healthcare_db?sslmode=require

# Redis (use managed Redis)
REDIS_URL=redis://your-redis-host:6379

# Email (AWS SES)
EMAIL_PROVIDER=ses
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=<your-key>
AWS_SECRET_ACCESS_KEY=<your-secret>
EMAIL_FROM_ADDRESS=noreply@yourdomain.com

# CORS (restrict to your frontend)
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Rate Limiting
RATE_LIMIT_RPS=50
RATE_LIMIT_BURST=100
```

### Deploy to Render.com

1. Create new Web Service
2. Connect repository
3. Set environment variables
4. Deploy automatically on push

### Deploy with Docker

```bash
docker build -t healthcare-access-connector:latest .
docker run -p 8080:8080 --env-file .env.production healthcare-access-connector:latest
```

## 🔒 Security & HIPAA Compliance

### Implemented
- ✅ Encrypted passwords (bcrypt)
- ✅ JWT with expiration
- ✅ Rate limiting per IP
- ✅ CORS protection
- ✅ Input validation
- ✅ SQL injection protection
- ✅ Secure headers
- ✅ Audit logging

### Recommended for Production
- 🔲 TLS/HTTPS (via load balancer)
- 🔲 Database encryption at rest
- 🔲 PHI data encryption
- 🔲 Audit trail for all data access
- 🔲 Regular security audits
- 🔲 HIPAA Business Associate Agreement (BAA)
- 🔲 Data backup and disaster recovery

## 📊 Monitoring

### Prometheus Metrics Available
- HTTP request duration
- Request count by endpoint
- Appointment booking rates
- Database query performance
- Cache hit rates
- Email delivery status

### Logs
Structured JSON logs (production) or console (development)

## 🗺️ Roadmap

- [x] Patient registration and authentication
- [x] Provider registration and profiles
- [x] Appointment booking system
- [x] Email notifications
- [x] Provider search
- [ ] Real-time availability checking
- [ ] Insurance verification API integration
- [ ] Telemedicine video calls
- [ ] Medical records management
- [ ] Prescription management
- [ ] Payment processing
- [ ] Patient reviews and ratings
- [ ] Provider analytics dashboard
- [ ] Mobile app integration
- [ ] SMS notifications (Twilio)
- [ ] Multi-language support
- [ ] FHIR API compliance

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Add tests
5. Run `make check`
6. Submit pull request

## 📄 License

MIT License - see LICENSE file

## 📞 Support

- Create GitHub issue
- Check documentation
- Review API examples

---

**Healthcare Access Made Simple** 🏥 | Built with ❤️ using Go
