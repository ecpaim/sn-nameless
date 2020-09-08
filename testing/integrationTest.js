const createServer = require('./server');
const request = require('supertest');


describe("General tests", function() {
    const app = createServer();

    let token;

    it('signup test empty fields', function(done) {

        request(app)
        .post('/api/signup')
        .send({
            username: "",
            email: "",
            password: "",
            confirmPassword: "12345"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(400, {
            errors: {
              email: "Must not be empty",
              username: "Must have at least 3 characters",
              password: "Must have at least 6 characters",
              confirmPassword: "Passwords must match"
            },
            success: false
          }, done);
    });

    it('signup test wrong password', function(done) {

        request(app)
        .post('/api/signup')
        .send({
            username: "user",
            email: "user@email.com",
            password: "123456",
            confirmPassword: "12345"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(400, {
            errors: {
                confirmPassword:"Passwords must match"
            },
            success: false
        })
        .end(done);
    });

    it('signup test correct form', function(done) {

        request(app)
        .post('/api/signup')
        .send({
            username: "user2",
            email: "user2@email.com",
            password: "654321",
            confirmPassword: "654321"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(function(res) {
            if(typeof res.body.token.token === 'string')
                return;
            else {
                throw new Error("Did not return a token")
            }
        })
        .end(done);
    });

    it('login empty password', function(done) {
        
        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "user",
            password: ""
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(400, {
            errors: {
                emailOrUser: 'Invalid credentials',
                password: 'Must not be empty'
            },
            success: false
        })
        .end(done);
    });

    it('login test dumb SQL injection', function(done) {
        
        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "DROP TABLE",
            password: "654321"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(400, {
            errors: {
                emailOrUser: 'Invalid Email or Username'
            },
            success: false
        })
        .end(done);
    });

    it('login test email form', function(done) {

        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "user2@email.com",
            password: "654321"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(function(res) {
            if(typeof res.body.token.token === 'string')
                return;
            else {
                throw new Error("Did not return a token")
            }
        })
        .end(done);
    });

    it('login test user form', function(done) {

        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "user2",
            password: "654321"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(function(res) {
            if(typeof res.body.token.token === 'string'){
                token = res.body.token.token;
                return;
            } else {
                throw new Error("Did not return a token")
            }
        })
        .end(done);
    });
    it('acessing protected route with fresh token', function(done) {
        
        request(app)
        .get('/api/protected')
        .set('Content-Type','application/json')
        .set('Authorization',token)
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(200, {success: true, msg: 'you entered the protected route'})
        .end(done);
    });


});

     

