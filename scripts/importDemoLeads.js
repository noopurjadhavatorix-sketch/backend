require('dotenv').config();
const mongoose = require('mongoose');
const Lead = require('../models/lead');

// Demo leads data from the image
const demoLeads = [
  {
    name: 'priyanshu',
    email: 'p@gmail.com',
    phone: '9028415678',
    company: 'capgemini',
    role: 'demo_request_page',
    interests: ['SAP Support'],
    status: 'new',
    source: 'import',
    metadata: {
      priority: 'Medium',
      originalSource: 'demo_request_page'
    }
  },
  {
    name: 'kkk',
    email: 'k@gmail.com',
    phone: '123456783',
    company: 'jj',
    role: 'demo_request_page',
    interests: ['SAP Migration'],
    status: 'new',
    source: 'import',
    metadata: {
      priority: 'Medium',
      originalSource: 'demo_request_page'
    }
  },
  {
    name: 'hjkhfkl',
    email: 'k@gmail.com',
    phone: '9028415678',
    company: 'Inn',
    role: 'demo_request_page',
    interests: ['SAP Implementation'],
    status: 'new',
    source: 'import',
    metadata: {
      priority: 'Medium',
      originalSource: 'demo_request_page'
    }
  },
  {
    name: 'bcn',
    email: 'k@gmail.com',
    phone: '8080127991',
    company: 'inn',
    role: 'demo_request_page',
    interests: ['SAP Implementation'],
    status: 'new',
    source: 'import',
    metadata: {
      priority: 'Medium',
      originalSource: 'demo_request_page'
    }
  },
  {
    name: 'dvcds',
    email: 'j@gmail.com',
    phone: '5014620315',
    company: 'scn',
    role: 'demo_request_page',
    interests: ['SAP Implementation'],
    status: 'new',
    source: 'import',
    metadata: {
      priority: 'Medium',
      originalSource: 'demo_request_page'
    }
  }
];

async function importDemoLeads() {
  try {
    // Connect to MongoDB using the leads database
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected...');

    // Check if any of these leads already exist (based on email and phone)
    const existingLeads = await Lead.find({
      $or: demoLeads.map(lead => ({
        $or: [
          { email: lead.email },
          { phone: lead.phone }
        ]
      }))
    });

    const existingEmails = new Set(existingLeads.map(lead => lead.email));
    const existingPhones = new Set(existingLeads.map(lead => lead.phone));

    // Filter out leads that already exist
    const newLeads = demoLeads.filter(lead => 
      !existingEmails.has(lead.email) && !existingPhones.has(lead.phone)
    );

    if (newLeads.length === 0) {
      console.log('All demo leads already exist in the database.');
      process.exit(0);
    }

    // Insert new leads
    const createdLeads = await Lead.insertMany(newLeads);
    console.log(`Successfully imported ${createdLeads.length} new demo leads`);

    process.exit(0);
  } catch (error) {
    console.error('Error importing demo leads:', error);
    process.exit(1);
  } finally {
    mongoose.connection.close();
  }
}

importDemoLeads();
