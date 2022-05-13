const jwt = require('jsonwebtoken');

function auth(req, res, next) {
    const token = req.header('Authorization');

    //Check for token
    if(!token) 
        return res.status(400).json({
        "result": false,
        "error": "Please provide a JWT token"
    });


    try {
        // Verify token 
        const decoded = jwt.verify(token, 'supersecret');

        //Add user from payload
        req.user = decoded;
        next();
    } catch(e){
        res.status(400).json({ 
            "result": false,
            "error": "JWT Verification Failed"
         });
    }
}

module.exports = auth;
