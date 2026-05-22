const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 8 // Enforcing a basic standard
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'superadmin'],
        default: 'user' // Role-Based Access Control foundation
    }
}, { timestamps: true });

// Mongoose Pre-Save Hook: This runs right before the user is saved to MongoDB
UserSchema.pre('save', async function(next) {
    const user = this;

    // Only hash the password if it has been modified (or is new)
    if (!user.isModified('password')) return next();

    try {
        // Generate a salt (random data added to the password before hashing)
        const salt = await bcrypt.genSalt(10);
        // Hash the password with the salt
        user.password = await bcrypt.hash(user.password, salt);
        next();
    } catch (error) {
        return next(error);
    }
});

// Helper method to compare passwords during login
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);