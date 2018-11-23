let express = require('express');
let bodyparser = require('body-parser');
let mongoose = require('mongoose');
let jwt = require('jsonwebtoken');

const cors = require('cors');
let https = require('https');
const fs = require('fs');
let helmet = require('helmet');
const crypto = require('crypto')



let app = express();

// adding https
const options = {
    key: fs.readFileSync('./ssl/serverkey.key'),
    cert: fs.readFileSync('./ssl/server.crt')
};

// using cors to restrict usage
app.use(cors({origin: [
    "https://localhost:4200"
], credentials: true}));


// helmet() init!
app.use(helmet());

// block X-Powered-By
app.disable('x-powered-by');


// Database connections
mongoose.connect("mongodb://localhost/resturant", { useNewUrlParser: true }).then(
        () => {console.log("DB connected.")},
        err => {console.log(err)}
    );
let db = mongoose.connection;

// bodyparser init 
app.use(bodyparser.json({
    extended: true      // to support JSON-encoded bodies
}));



// loading schema
let Staff = require('./schema/foodrunner-schema');



// api routes ---- ------ api connect

// init connection
app.get('/signup', (req, res) => {
    let _req_ip = req.ip;
    let hmac = crypto.createHmac('SHA256', 'lxmL7VIdPUuhHuTrXzDqG5IYwjEuTwZ6');
    hmac.update(uuidv4() + _req_ip + new Date());
    let __sess_id = hmac.digest('hex');
    hmac = crypto.createHmac('SHA256', 'lxmL7VIdPUuhHuTrXzDqG5IYwjEuTwZ6');
    hmac.update(uuidv4() + new Date());
    let __xsrf = hmac.digest('hex');
    // console.log(__sess_id);
    // console.log(__xsrf);
    
    let _sess_data = {
        "iss": "https://localhost:4200/",
        "session_id": __sess_id
    }

    jwt.sign({_sess_data}, '4E37F6EB24C177F499C491BB9748EEE2118D8F2F984E37F6AAC40F356ECCEW8I', {expiresIn: '12h'}, (err, token) =>{
        let _xsrf_data = {
            "iss": "https://localhost:4200/",
            "x_session_id": __sess_id,
            "xsrfToken": __xsrf
        }
        __sess = token;
        jwt.sign({_xsrf_data}, 'B48D53C2347C923E348E8E3574392923E343D53C2347CB4997CB5FCCBDB5FCCBD8EBDC491BB9748EEE', {expiresIn: '15m'}, (err, x_token) =>{
            let _data = {
                "iss": "https://localhost:4200/",
                "x_sess_id": __sess,
                "xsrfToken": x_token
            }
            res.send({
                _data
            });
        });
    });

    console.log("Authenticated New Session ... \nAt IP:", _req_ip);
});


// refresh token --signup
app.get('/signup/refresh', authenticationCheck, (req, res) => {
    hmac = crypto.createHmac('SHA256', 'lxmL7VIdPUuhHuTrXzDqG5IYwjEuTwZ6');
    hmac.update(uuidv4() + new Date());
    let __xsrf = hmac.digest('hex');
    let _xsrf_data = {
        "iss": "https://localhost:4200/",
        "x_session_id": req.token,
        "xsrfToken": __xsrf
    }
    jwt.sign({_xsrf_data}, 'B48D53C2347C923E348E8E3574392923E343D53C2347CB4997CB5FCCBDB5FCCBD8EBDC491BB9748EEE', {expiresIn: '15m'}, (err, x_token) =>{
        let _data = {
            "iss": "https://localhost:4200/",
            "x_sess_id": req.headers['authorization'],
            "xsrfToken": x_token
        }
        res.send({
            _data
        });
    });
});


//signup --staff
app.post('/signup/register', authenticationCheck, (req, res) => {
    let staffData = req.body.staffData;
    // console.log(staffData);
    hmac = crypto.createHmac('SHA256', 'ac8xtoX5xWh7dxu3Zu2LMz0u444XaYCBnZIEMJZO1zg=');
    hmac.update(staffData.email + req.token + new Date());
    userSessionToken = hmac.digest('hex');
    // console.log(userSessionToken);

    // staff signup function
    Staff.staffSignUp(staffData, userSessionToken, (err, staff) => {
        if(err){
            res.send({
                "status": 403,
                "message": "Could not register your Account! Error: " + err,
            });
        } else {
            user_data = {
                "_usid_": userSessionToken,
                "acc": ["/profile", "/order", "/cart"],
                "issuer": "https://localhost:4200/",
            }
            jwt.sign({user_data}, '472B4B6250655367566B5970337336763979244226452948404D635166546A57', {expiresIn: '12h'}, (err, token) =>{
                let _data = {
                    "iss": "https://localhost:4200/",
                    "__usid": token,
                    "status": 200,
                    "message": "Sign Up Successful!",
                    "route": "/profile"
                }
                res.send({
                    _data
                });
            });
        }
    });
});



function verifyDomain(req, res, next) {
    let pattern = /^(https:\/\/localhost:4200\/)/g
    // for deployment
    let reqHeaderHost = req.get('Referer');

    if(pattern.exec(reqHeaderHost)) {
        next();
    } else {
      // Forbidden
      res.sendStatus(403);
    }  
}


function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
}


// Authentication
function authenticationCheck(req, res, next){
    let pattern = /^(https:\/\/localhost:4200\/)/g
    if(pattern.exec(req.get('Referer'))) {
        sessId = req.headers['authorization'];
        jwt.verify(sessId, '4E37F6EB24C177F499C491BB9748EEE2118D8F2F984E37F6AAC40F356ECCEW8I', (err, authData) => {
            if(err){
                res.send({"status": 403, "message": "Unable to verify Session."});
            } else {
                xsrfId = req.get('X-XSRF-Token');
                jwt.verify(xsrfId, 'B48D53C2347C923E348E8E3574392923E343D53C2347CB4997CB5FCCBDB5FCCBD8EBDC491BB9748EEE', (err, xauthData) => {
                    if(err){
                        res.send({"status": 403, "message": "Session Expired. Please Refresh the page."});
                    } else {
                        if(authData._sess_data.session_id === xauthData._xsrf_data.x_session_id){
                            req.token = authData._sess_data.session_id;
                            next();
                        } else {
                            res.send({"status": 403, "message": "Unable to verify tokens."});
                        }
                    }
                });   
            }
        });
    } else {
      // Forbidden
      res.send({"status": 403, "message": "Unable to verify domain."});
    }     
}



// server starting (.listen)
https.createServer(options, app).listen(3000, ()=>{console.log("Server running on Port 3000, https://localhost:3000/?")});