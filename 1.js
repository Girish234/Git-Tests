
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');


const app = express();
const PORT = process.env.PORT || 3000;

const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'employees'
});

app.use(express.json());

app.get('/', (req, res) => {
    res.send('JWT Authentication API is running');
});

// TODO 1: POST /register
// Read username and password from req.body.
// Validate that both are strings and the password is at least 8 characters.
// Hash the password using bcrypt.hash(password, 10).
// Insert username and password_hash into the users table using ? placeholders.
// Return 201 on success and handle duplicate usernames.
app.post('/register',async (req,res)=>{
    const {username,password}=req.body;
    if(typeof username !=='string' || typeof password !=='string' || password.length<8){
        return res.status(404).json({error:"Provide correct username and pasword(min 8 characters)"});
    }
    const passwordHash=await bcrypt.hash(password,10);
    const query='Insert into users(username,password_hash) values(?,?)';
    db.query(query,[username.trim(),passwordHash],(err,results)=>{
        if(err){
            if(err.code==='ER_DUP_ENTRY'){
                return res.status(409).json({
                            error: 'Username already exists'
                        }); 
            }
            return res.status(500).json({error:"Failed to insert data into DB"});
        }
        return res.status(201).json({
            message:"succesfully registered the user!!",
            userID:results.insertId
        });
    });
});
// TODO 2: POST /login
// Read username and password from req.body.
// Find the user by username using a parameterized SQL query.
// If the user does not exist, return 401.
// Compare the submitted password with user.password_hash using bcrypt.compare().
// If incorrect, return 401.
// If correct, create a JWT using jwt.sign() with the user's ID and username.
// Use process.env.JWT_SECRET and expiresIn: '1h'.
// Return the token as JSON.

app.post('/login',(req,res)=>{
    const {username,password}=req.body;
    if(typeof username !=='string' || typeof password !=='string' || password.length<8){
        return res.status(404).json({error:"Provide correct username and pasword(min 8 characters)"});
    }
    const query='select * from users where username=?';
    db.query(query,[username.trim()],async (err,results)=>{
        if(err){
            return res.status(401).json({error:"user doesnt exist by the username"});
        }
        if(results.length ===0){
            return res.status(401).json({error:"Invalid username or password"});
        }
        const user=results[0];
        try{
            const passwordMatches=await bcrypt.compare(password,user.password_hash);
            if(!passwordMatches){
                return res.status(401).json({error:"Invalid password"});
            }
            const token=jwt.sign(
                { userId: user.id, username: user.username },
                process.env.JWT_SECRET,
                {expiresIn:'1h'}
            );
            res.status(201).json({
                message:"Login sucessfull",
                autherization:"Bearer",
                token:token
            });
        }catch(error){
            return res.status(404).json({error:"Error occured logging"});
        }
    });
});

// TODO 3: Create authenticateToken middleware
// Read req.headers.authorization.
// Check that it starts with 'Bearer '.
// Extract the token.
// Verify it with jwt.verify(token, process.env.JWT_SECRET).
// If missing or invalid, return 401.
// If valid, assign the decoded payload to req.user and call next().
function authenticateToken(req,res,next){
    const authHeader = req.headers.authorization;;
    if(!authHeader || !authHeader.startsWith('Bearer ')){
        return res.status(401).json({error:'Authentication required'});
    }
    const token=authHeader.split(' ')[1];
    try{
        const decoded=jwt.verify(token,process.env.JWT_SECRET);
        req.user=decoded;
        next();
    }catch (err) {
        return res.status(401).json({
            error: 'Invalid or expired token'
        });
    }

}

// TODO 4: GET /profile
// Apply authenticateToken middleware.
// Return a success message and the authenticated user's ID and username.
app.get('/profile', authenticateToken, (req, res) => {
    const query =
        'SELECT id, username FROM users WHERE id = ?';

    db.query(query, [req.user.userId], (err, results) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error'
            });
        }

        if (results.length === 0) {
            return res.status(401).json({
                error: 'User no longer exists'
            });
        }

        return res.status(200).json({
            message: 'Authenticated successfully',
            user: results[0]
        });
    });
});


// Unknown routes
app.use((req, res) => {
    res.status(404).json({ error: 'Unknown route' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
