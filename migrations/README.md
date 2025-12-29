# Database Migrations

This directory contains database migration scripts for the Atorix IT application.

## Available Migrations

### 20241204_migrate_submissions_to_demo_requests.js
- **Description**: Migrates data from the `submissions` collection to the new `demo_requests` collection with an updated schema.
- **Changes**:
  - Creates a new `demo_requests` collection
  - Transforms and migrates all documents from `submissions` to `demo_requests`
  - Adds proper indexes for better query performance
  - Preserves original data in a `metadata` field

## How to Run Migrations

### Prerequisites
- MongoDB shell (`mongosh`) installed
- MongoDB server running locally or connection string to your MongoDB instance

### Running a Migration

1. Navigate to the migrations directory:
   ```bash
   cd backend/migrations
   ```

2. Run the migration using `mongosh`:
   ```bash
   mongosh "mongodb://[username:password@]host:port/" 20241204_migrate_submissions_to_demo_requests.js
   ```

   For example, for a local MongoDB instance:
   ```bash
   mongosh "mongodb://localhost:27017/" 20241204_migrate_submissions_to_demo_requests.js
   ```

3. For production, use your MongoDB connection string:
   ```bash
   mongosh "mongodb+srv://username:password@cluster0.example.mongodb.net/" 20241204_migrate_submissions_to_demo_requests.js
   ```

### Verifying the Migration

After running the migration, you can verify the data in the MongoDB shell:

```javascript
// Connect to your database
use atorix_leads;

// Check counts
db.submissions.countDocuments();
db.demo_requests.countDocuments();

// View sample migrated data
db.demo_requests.find().limit(5).pretty();

// Verify indexes
db.demo_requests.getIndexes();
```

### Rolling Back (if needed)

If you need to rollback the migration:

```javascript
// Drop the demo_requests collection to undo the migration
use atorix_leads;
db.demo_requests.drop();
```

## Best Practices

1. **Always backup your database** before running migrations
2. Test migrations in a staging environment first
3. Run migrations during off-peak hours
4. Monitor the migration progress for large datasets
5. Keep migration scripts idempotent (safe to run multiple times)

## Adding New Migrations

1. Create a new file with the format: `YYYYMMDD_description_of_change.js`
2. Include a detailed header comment explaining the migration
3. Make the script idempotent
4. Test thoroughly before running in production
5. Update this README with information about the new migration
