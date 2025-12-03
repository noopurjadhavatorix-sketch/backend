# Atorix IT Backend API

This is the backend API for the Atorix IT website. It handles form submissions and leads management.

## Setup Instructions

1. **Install Dependencies**

```bash
cd backend
npm install
```

2. **Configure Environment Variables**

Create a `.env` file in the backend directory using the `.env.example` as a template:

```bash
cp .env.example .env
```

Then edit the `.env` file with your actual configuration values:

- Set `MONGODB_URI` to your MongoDB connection string
- Set `SENDGRID_API_KEY` to your SendGrid API key (for email notifications)
- Configure notification email addresses

3. **Start the Server**

For development (with auto-reload):

```bash
npm run dev
```

For production:

```bash
npm start
```

## API Endpoints

- `POST /api/submit` - Submit form data
- `GET /api/leads` - Get all leads (for admin usage)
- `DELETE /api/leads/:id` - Delete a lead (for admin usage)

## Required Environment Variables

- `MONGODB_URI`: MongoDB connection string
- `PORT`: Server port (defaults to 5001)
- `SENDGRID_API_KEY`: SendGrid API key for sending emails
- `NOTIFICATION_EMAIL`: Email where form notifications will be sent
- `SENDER_EMAIL`: Email address that will appear as the sender
