const jwt = require('jsonwebtoken');
require('dotenv').config();

const checktoken = (req, res, next)=>{
    const token = req.body.token || req.headers('access_token');

    if(!token){
        res.status(401).json({
            msg: "Access denied no token"
        })
    }

    else{
        try{
            const secret_key = process.env.JWT_SECRET;
            const decode = jwt.verify(token, secret_key);
            req.user = decode;
            next();
        }catch{
            req.status(401).json({
                msg: "invalid token"
            })
        }
    }




}