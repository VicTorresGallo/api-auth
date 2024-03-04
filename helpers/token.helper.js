'use strict'
const jwt = require('jwt-simple');
const moment = require('moment');
const SECRET = require('../config').SECRET;
const EXP_TIME = require('../config').TOKEN_EXP_TIME;

/*

*/

function creaToken( user ) {
    const payload = {
        sub: user._id,
        iat: moment().unix(),
        exp: moment().add(EXP_TIME, 'minutes').unix()
    };
    // console.log( { payload: payload });
    return jwt.encode(payload, SECRET);
}

function decodificaToken( token ) {
    return new Promise( (resolve, reject) => {
        try {
            const payload = jwt.decode( token, SECRET, false ); // Marcamos false para que verifique firma y caducidad
            resolve(payload.sub);// Si todo ha ido bien, devolvemos el id del usuario
        } catch (err) {
            reject( {
                status: 401,
                message: err.msg
            });
        }
    });
}
module.exports = {
    creaToken,
    decodificaToken
};