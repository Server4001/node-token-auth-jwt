// ============================
// get the packages we need ===
// ============================
var express     = require('express');
var app         = express();
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var mongoose    = require('mongoose');
var fs          = require('fs');

var jwt    = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file
var User   = require('./app/models/user'); // get our mongoose model

// ============================
// configuration ==============
// ============================
var port = process.env.PORT || 8080; // used to create, sign, and verify tokens
mongoose.connect(config.database); // connect to database
app.set('superSecret', config.secret); // secret variable

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

// ============================
// routes =====================
// ============================
// basic route
app.get('/', function(req, res) {
    res.send('Hello! The API is at http://localhost:' + port + '/api');
});

app.get('/setup', function(req, res) {
    // create a sample user
    var user = new User({
        name: 'Brice Bentler',
        password: 'supersecret', // Never do this in prod. Hashes are your friend.
        admin: true
    });

    // save the sample user
    user.save(function(err) {
        if (err) throw err;

        console.log('User saved successfully');
        res.json({ success: true });
    });
});

// Validating a token from the laravel app.
app.get('/jose/validate-token', function(req, res) {
    var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEyMywiaWF0IjoiMTQzNzI1MDc0NiJ9.lIDocm5ps0KE8Zh5piznxzc3xTTccfe6kZ7OCsF_biA";

    jwt.verify(token, app.get('superSecret'), function(err, decoded) {
        if (err) {
            return res.json({ success: false, message: 'Failed to authenticate token.' });
        } else {
            // if everything is good, save to request for use in other routes
            res.json({
                success: true,
                results: decoded
            });
        }
    });
});
// Validating a token from the laravel app using a .pem key.
app.get('/jose/validate-token-with-pem', function(req, res) {
    var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJ1aWQiOjEyMywiaWF0IjoiMTQzNzI3NzE3NCJ9.Rt0_nMWyYlE-x1UG9v7LSF06Yq-FDW0a_HsD0LtYIZcQz7pFlsnbk01w8oVerREQJ_kOqP9gKW6nAY6DLmGBnIdSzQIapWWXwyfk1v_NEVq_7sbta8PDGCTyKJxQ_SgDZcqVM7ewfYHCAr0jqhRaAnH3jjpTwnvxhzr5qFTjFHMKeeEEJckI0gHUYC64fsHZjLbfuqizjZjBnyNlQjsMEwLWTDYnmaFHbJkJKiZ4FGUIIsJTueyYATdC2VN_dislQkl_gjBr1Q-vwyufkcCjcEffuDe-8WPjxl6upcEcLTwOWd9p4id4uJhqQ1Lj-eOC5Ed7VSOEi64QBLLgOtm4jQ";

    var cert = fs.readFileSync('JWT-KEYS/jwt_rsa_2048_public.pem');

    jwt.verify(token, cert, {
        algorithms: ["RS512"]
    }, function(err, decoded) {
        if (err) {
            return res.json({ success: false, message: 'Failed to authenticate token.' });
        } else {
            res.json({
                success: true,
                results: decoded
            });
        }
    });
});
// Respond with a token for validation in the laravel app
app.get('/jose/get-token', function(req, res) {
    var token = jwt.sign({
        uid: 123,
        iat: "1437250128"
    }, app.get('superSecret'), {
        expiresInMinutes: 1440 // expires in 24 hours
    });

    // return the information including token as JSON
    res.json({
        success: true,
        message: 'Enjoy your token!',
        token: token
    });
});
// Respond with a token for validation in the laravel app, using a .pem key
app.get('/jose/get-token-with-pem', function(req, res) {
    var cert = fs.readFileSync('JWT-KEYS/jwt_rsa_2048_private.pem');  // get private key

    var token = jwt.sign({
        uid: 123,
        iat: "1437250128"
    }, cert, {
        expiresInMinutes: 1440, // expires in 24 hours
        algorithm: "RS512"
    });

    res.json({
        success: true,
        message: 'Enjoy your token!',
        token: token
    });
});

var apiRoutes = express.Router();

// Route to authenticate a user (POST http://localhost:8080/api/authenticate)
apiRoutes.post('/authenticate', function(req, res) {
    // find the user
    User.findOne({
        name: req.body.name
    }, function(err, user) {
        if (err) {
            throw err;
        }

        if (!user) {
            res.json({ success: false, message: 'Authentication failed. User not found.' });
        } else if (user) {
            // check if password matches
            if (user.password !== req.body.password) {
                res.json({ success: false, message: 'Authentication failed. Wrong password.' });
            } else {
                // if user is found and password is right
                // create a token
                var token = jwt.sign(user, app.get('superSecret'), {
                    expiresInMinutes: 1440 // expires in 24 hours
                });

                // return the information including token as JSON
                res.json({
                    success: true,
                    message: 'Enjoy your token!',
                    token: token
                });
            }

        }

    });
});

// Route middleware to verify a token
apiRoutes.use(function(req, res, next) {
    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    // decode token
    if (token) {
        // verifies secret and checks exp
        jwt.verify(token, app.get('superSecret'), function(err, decoded) {
            if (err) {
                return res.json({ success: false, message: 'Failed to authenticate token.' });
            } else {
                // if everything is good, save to request for use in other routes
                req.decoded = decoded;
                next();
            }
        });
    } else {
        // if there is no token, return an error
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        });

    }
});

// route to show a random message (GET http://localhost:8080/api/)
apiRoutes.get('/', function(req, res) {
    res.json({ message: 'Welcome to the coolest API on earth!' });
});

// route to return all users (GET http://localhost:8080/api/users)
apiRoutes.get('/users', function(req, res) {
    User.find({}, function(err, users) {
        res.json(users);
    });
});

// apply the routes to our application with the prefix /api
app.use('/api', apiRoutes);

// API ROUTES -------------------
// we'll get to these in a second

// =======================
// start the server ======
// =======================
app.listen(port);
console.log('Magic happens at http://localhost:' + port);
