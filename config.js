module.exports = {
    PORT: process.env.PORT || 4100,
    DB: process.env.MONGODB || 'mongodb://localhost:27017/SD',
    TOKEN: '1234',
    SECRET: 'secreto',
    TOKEN_EXP_TIME: 7*24*70
    }