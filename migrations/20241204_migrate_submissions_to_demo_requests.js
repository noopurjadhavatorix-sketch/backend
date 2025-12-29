/**
 * Migration: Move data from submissions collection to demo_requests collection
 * Created: 2024-12-04
 * Description: Migrates submission documents to the new demo_requests collection with updated schema
 */

print('Starting migration: submissions to demo_requests');

// Connect to the admin database to check if the target database exists
const adminDb = db.getSiblingDB('admin');
const dbs = adminDb.adminCommand('listDatabases').databases.map(db => db.name);

if (!dbs.includes('atorix_leads')) {
  print('Error: Database "atorix_leads" does not exist');
  quit(1);
}

// Connect to the target database
const db = db.getSiblingDB('atorix_leads');

// Create demo_requests collection if it doesn't exist
db.createCollection('demo_requests');

// Get all submissions
const submissions = db.submissions.find().toArray();
const totalSubmissions = submissions.length;

print(`Found ${totalSubmissions} submissions to migrate`);

let successCount = 0;
let errorCount = 0;

// Process each submission
submissions.forEach((submission, index) => {
  try {
    // Create a new demo request with the submission data
    const demoRequest = {
      name: submission.name || '',
      email: submission.email || '',
      phone: submission.phone || '',
      company: submission.company || 'N/A',
      role: submission.role || 'Website Visitor',
      interests: submission.interests || ['General Inquiry'],
      message: submission.message || 'No message provided',
      source: submission.source || 'website',
      status: submission.status || 'new',
      metadata: {
        ...(submission.metadata || {}),
        priority: submission.priority || 'medium',
        value: submission.value || '$0',
        location: submission.location || 'N/A',
        migratedFrom: 'submissions',
        originalId: submission._id
      },
      createdAt: submission.createdAt || new Date(),
      updatedAt: new Date()
    };

    // Insert into demo_requests collection
    const result = db.demo_requests.insertOne(demoRequest);
    
    if (result.insertedId) {
      successCount++;
      print(`[${index + 1}/${totalSubmissions}] Migrated submission ${submission._id} to demo_requests as ${result.insertedId}`);
    } else {
      errorCount++;
      print(`[${index + 1}/${totalSubmissions}] Failed to migrate submission ${submission._id}`);
    }
  } catch (error) {
    errorCount++;
    print(`[${index + 1}/${totalSubmissions}] Error migrating submission ${submission._id}: ${error.message}`);
  }
});

// Create indexes on demo_requests collection
try {
  db.demo_requests.createIndex({ email: 1 });
  db.demo_requests.createIndex({ status: 1 });
  db.demo_requests.createIndex({ 'metadata.priority': 1 });
  db.demo_requests.createIndex({ createdAt: -1 });
  print('Created indexes on demo_requests collection');
} catch (error) {
  print(`Error creating indexes: ${error.message}`);
}

// Verify counts
const finalSubmissionCount = db.submissions.countDocuments();
const finalDemoRequestCount = db.demo_requests.countDocuments();

print('\nMigration Summary:');
print('================================');
print(`Total submissions: ${totalSubmissions}`);
print(`Successfully migrated: ${successCount}`);
print(`Failed to migrate: ${errorCount}`);
print(`Final submissions count: ${finalSubmissionCount}`);
print(`Final demo_requests count: ${finalDemoRequestCount}`);
print('================================');

if (successCount === totalSubmissions) {
  print('\nMigration completed successfully!');
  print('To verify the data, run the following commands:');
  print('1. db.demo_requests.find().limit(5) - Check sample migrated data');
  print('2. db.demo_requests.countDocuments() - Verify total count');
  print('\nOnce verified, you can safely drop the submissions collection with:');
  print('db.submissions.drop()');
} else {
  print('\nMigration completed with errors. Please check the logs above.');
}

print('\nMigration completed at: ' + new Date().toISOString());
