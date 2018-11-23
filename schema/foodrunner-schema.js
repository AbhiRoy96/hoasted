let mongoose = require('mongoose');
let bcrypt = require('bcryptjs');
SALT_WORK_FACTOR = 10;


let StaffSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true, trim: true },
  username: { type: String, unique: true, required: true, trim: true },
  contactnumber: {type: String, unique:true, required: true, trim:true},
  password: { type: String, required: true, trim:true },
  passwordConf: { type: String, required: true, trim:true },
  session_key: { type: String, trim:true },
  last_access_on: { type: Date, trim:true }
});


let Staff = module.exports = mongoose.model('Staff', StaffSchema, 'staff');



module.exports.staffSignUp = (staffData, s_token, callback) => {
    console.log("Staff-Signup Api Requested!");

    let newStaff = new Staff(staffData);
    bcrypt.genSalt(SALT_WORK_FACTOR, (err, salt) => {
        if(err) console.log(err);
        else {
            bcrypt.hash(newStaff.password, salt, (err, hash) => {
                if(err) console.log(err);
                else{
                    newStaff.password = hash;
                    newStaff.passwordConf = hash;
                    newStaff.session_key = s_token;
                    newStaff.last_access_on = new Date();
                    newStaff.save(callback)
                }
            });
        }
    });
}