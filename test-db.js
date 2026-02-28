require('dotenv').config({ path: '.env.local' });
const { Client } = require('pg');

async function testConnection() {
    const client = new Client({
        connectionString: process.env.POSTGRES_URL_NON_POOLING,
        ssl: { rejectUnauthorized: false }
    });

    try {
        console.log('Connecting to Neon DB (pg driver)...');
        await client.connect();
        
        const timeRes = await client.query('SELECT NOW()');
        console.log('✅ Connected successfully!');
        console.log('✅ Server time:', timeRes.rows[0].now);
        
        const usersRes = await client.query('SELECT count(*) FROM users').catch(() => ({ rows: [] }));
        if(usersRes.rows.length) {
            console.log('✅ Users table count:', usersRes.rows[0].count);
        } else {
            console.log('⚠️ Users table not found.');
        }

        const codesRes = await client.query('SELECT count(*) FROM redeemed_codes').catch(() => ({ rows: [] }));
        if(codesRes.rows.length) {
            console.log('✅ Redeemed codes count:', codesRes.rows[0].count);
        } else {
            console.log('⚠️ Redeemed codes table not found.');
        }

        console.log('Database URL is valid and connection is fully operational.');
        process.exit(0);
    } catch (err) {
        console.error('❌ Connection failed:', err.message);
        process.exit(1);
    } finally {
        await client.end();
    }
}

testConnection();
