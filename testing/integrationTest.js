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

    it('signup test username too long', function(done) {

        request(app)
        .post('/api/signup')
        .send({
            username: "user123456789123456789",
            email: "user@email.com",
            password: "123456",
            confirmPassword: "123456"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(400, {
            errors: {
                username: 'Must have at most 20 characters'
            },
            success: false
        })
        .end(done);
    });

    it('signup test email already in use', function(done) {

        request(app)
        .post('/api/signup')
        .send({
            username: "ANEWUSER",
            email: "user2@email.com",
            password: "654321",
            confirmPassword: "654321"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(function(res) {
            if(res.body.errors.email === "Email already being used.")
                return;
            else {
                throw new Error("failed to find email");
            }
        })
        .end(done);
    });

    it('signup test username already in use', function(done) {

        request(app)
        .post('/api/signup')
        .send({
            username: "user2",
            email: "ANEWEMAIL@email.com",
            password: "654321",
            confirmPassword: "654321"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(function(res) {
            if(res.body.errors.username === "Username already being used.")
                return;
            else {
                throw new Error("failed to find username");
            }
        })
        .end(done);
    });

    it('signup test correct form', function(done) {

        request(app)
        .post('/api/signup')
        .send({
            username: "deletethis",
            email: "delete@this.com",
            password: "123&&&&",
            confirmPassword: "123&&&&"
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

    it('login test email form wrong password', function(done) {

        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "delete@this.com",
            password: "123&&&4"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(401, { errors: { password: 'Invalid password'}, success: false })
        .end(done);
    });

    it('login test email form correct', function(done) {

        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "delete@this.com",
            password: "123&&&&"
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

    it('login test username form wrong password', function(done) {

        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "deletethis",
            password: "123&&&4"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(401, { errors: { password: 'Invalid password'}, success: false })
        .end(done);
    });

    it('login test username form wrong username', function(done) {

        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "deletethi",
            password: "123&&&&"
        })
        .set('Content-Type','application/json')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(401, { errors: { emailOrUser: 'Couldnt find email or username'}, success: false})
        .end(done);
    });

    
    it('login test username form', function(done) {

        request(app)
        .post('/api/login')
        .send({
            emailOrUser: "deletethis",
            password: "123&&&&"
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

    it('acessing protected route with wrong token', function(done) {
        
        request(app)
        .get('/api/protected')
        .set('Content-Type','application/json')
        .set('Authorization','jsdoifjosidjfoisdjfoisjdfoisjdofijs')
        .expect(401, 'Unauthorized')
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

    it('acessing protected route with fresh token', function(done) {
        
        request(app)
        .get('/api/protected')
        .set('Content-Type','application/json')
        .set('Authorization',token)
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(200, {success: true, msg: 'you entered the protected route'})
        .end(done);
    });

    it('delete user with wrong password', function(done) {
        
        request(app)
        .post('/api/exc')
        .send({
            password: "wrong123"
        })
        .set('Content-Type','application/json')
        .set('Authorization',token)
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(400, {success: false, msg: 'Invalid password'})
        .end(done);
    });
    it('delete user with correct password', function(done) {
        
        request(app)
        .post('/api/exc')
        .send({
            password: "123&&&&"
        })
        .set('Content-Type','application/json')
        .set('Authorization',token)
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(200, {success: true, msg: 'User removed successfully'})
        .end(done);
    });
    

});

     

