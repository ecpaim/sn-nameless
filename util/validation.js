/*
    Generic form validation: check email,password and username fields for obvious sanitization and mistakes
    Does not make any DB call
*/
const isValidEmail =(email) => {
    //checks for email pattern
    const emailRegEx = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    
    if(email.match(emailRegEx)) return true;
    else return false;
};
// helper to see if string is empty
const isEmpty = (string) => {
    if(string.trim() === '') return true;
    else return false;
};
const isValidUsername = (username) => {
    const userRegex = "^[A-Za-z0-9_-]{3,}$";
    if(username.match(userRegex)) return true;
    else return false;
}
const isValidPassword = (password) => {
    const userRegex = "^[A-Za-z0-9@#$%&*?]{6,}$";
    if(password.match(userRegex)) return true;
    else return false;
}

exports.validateSignupData = (data) => {
    let errors = {};
    if(data.email){
        if(!isValidEmail(data.email)) errors.email = 'Must be a valid email address';
        if(isEmpty(data.email)) errors.email = 'Must not be empty';
    } else {
        errors.email = 'Must not be empty';
    }

    if(data.username){
        if(!isValidUsername(data.username)) errors.username = 'Must have just numbers, letters and dashes';
        if(data.username.trim().length < 3) errors.username = 'Must have at least 3 characters';
        if(data.username.trim().length > 20) errors.username = 'Must have at most 20 characters';
    } else {
        errors.username = 'Must have at least 3 characters';
    }

    if(data.password){
        if(!isValidPassword(data.password)) errors.password = 'Must have just numbers, letters and @ # $ % & * ? as special characters';
        if(data.password.trim().length < 6) errors.password = 'Must have at least 6 characters';
        if(data.password.trim().length > 40) errors.password = 'Must have at most 40 characters';

        if(data.password !== data.confirmPassword) errors.confirmPassword = 'Passwords must match';
    } else {
        errors.password = 'Must have at least 6 characters';
        errors.confirmPassword = 'Passwords must match';
    }

    
    return {
        errors,
        valid: Object.keys(errors).length === 0 ? true : false
    }
};

exports.validateLoginData = (data) => {
    let errors = {};
    let email;

    if(data.emailOrUser){
        if(isValidEmail(data.emailOrUser)){
            email = true;
        }
        else if(isValidUsername(data.emailOrUser)) {
            email = false;
        }
        else {
            errors.emailOrUser = 'Invalid Email or Username';
        }
        if(isEmpty(data.emailOrUser)) errors.emailOrUser = 'Must not be empty';


    } else {
        errors.emailOrUser = 'Must not be empty';
    }

    if(data.password){
        if(!isValidPassword(data.password)) errors.emailOrUser = 'Invalid credentials';
        if(isEmpty(data.password)) errors.password = 'Must not be empty';
    } else {
        errors.emailOrUser = 'Invalid credentials';
        errors.password = 'Must not be empty';
    }

    return {
        errors,
        valid: Object.keys(errors).length === 0 ? true : false,
        email
    }
};

exports.validateText = (str) => { // protects against cross-site scripting (XSS)
    var res = str.replace(">","&gt;");
    res = res.replace("<","&lt;");
    return res;
}